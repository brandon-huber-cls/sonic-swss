```cpp
#include <fstream>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <cerrno>
#include <climits>
#include "logger.h"
#include "dbconnector.h"
#include "producerstatetable.h"
#include "tokenize.h"
#include "ipprefix.h"
#include "timer.h"
#include "buffermgrdyn.h"
#include "bufferorch.h"
#include "exec.h"
#include "shellcmd.h"
#include "schema.h"
#include "warm_restart.h"

#include "buffer/bufferschema.h"

/*
 * Some Tips
 * 1. All keys in this file are in format of APPL_DB key.
 *    Key population:
 *        On receiving item update from CONFIG_DB: key has been transformed into the format of APPL_DB
 *        In internal maps: table name removed from the index
 * 2. Maintain maps for pools, profiles and PGs in CONFIG_DB and APPL_DB
 * 3. Keys of maps in this file don't contain the TABLE_NAME
 */
using namespace std;
using namespace swss;

static constexpr int BUFFER_PROFILE_SYNC_MAX_CHECKS = 30;

// Helper function to safely convert string to long with validation
static bool safeStringToLong(const string &str, long &result, long minVal = LONG_MIN, long maxVal = LONG_MAX)
{
    if (str.empty())
    {
        return false;
    }

    char *endptr = nullptr;
    errno = 0;
    long value = strtol(str.c_str(), &endptr, 10);

    // Check for conversion errors
    if (errno == ERANGE || (errno != 0 && value == 0))
    {
        SWSS_LOG_ERROR("String to long conversion failed for '%s': out of range", str.c_str());
        return false;
    }

    if (endptr == str.c_str())
    {
        SWSS_LOG_ERROR("String to long conversion failed for '%s': no digits found", str.c_str());
        return false;
    }

    if (*endptr != '\0')
    {
        SWSS_LOG_ERROR("String to long conversion failed for '%s': trailing characters", str.c_str());
        return false;
    }

    // Check range
    if (value < minVal || value > maxVal)
    {
        SWSS_LOG_ERROR("Value %ld is out of valid range [%ld, %ld]", value, minVal, maxVal);
        return false;
    }

    result = value;
    return true;
}

// Helper function to safely convert string to unsigned long with validation
static bool safeStringToULong(const string &str, unsigned long &result, unsigned long maxVal = ULONG_MAX)
{
    if (str.empty())
    {
        return false;
    }

    char *endptr = nullptr;
    errno = 0;
    unsigned long value = strtoul(str.c_str(), &endptr, 10);

    // Check for conversion errors
    if (errno == ERANGE)
    {
        SWSS_LOG_ERROR("String to unsigned long conversion failed for '%s': out of range", str.c_str());
        return false;
    }

    if (endptr == str.c_str())
    {
        SWSS_LOG_ERROR("String to unsigned long conversion failed for '%s': no digits found", str.c_str());
        return false;
    }

    if (*endptr != '\0')
    {
        SWSS_LOG_ERROR("String to unsigned long conversion failed for '%s': trailing characters", str.c_str());
        return false;
    }

    // Check range
    if (value > maxVal)
    {
        SWSS_LOG_ERROR("Value %lu exceeds maximum allowed value %lu", value, maxVal);
        return false;
    }

    result = value;
    return true;
}

BufferMgrDynamic::BufferMgrDynamic(DBConnector *cfgDb, DBConnector *stateDb, DBConnector *applDb, DBConnector *applStateDb, const vector<TableConnector> &tables, shared_ptr<vector<KeyOpFieldsValuesTuple>> gearboxInfo, shared_ptr<vector<KeyOpFieldsValuesTuple>> zeroProfilesInfo) :
        Orch(tables),
        m_platform(),
        m_bufferDirections{BUFFER_INGRESS, BUFFER_EGRESS},
        m_bufferObjectNames{"priority group", "queue"},
        m_bufferDirectionNames{"ingress", "egress"},
        m_applDb(applDb),
        m_zeroProfilesLoaded(false),
        m_supportRemoving(true),
        m_cfgDefaultLosslessBufferParam(cfgDb, CFG_DEFAULT_LOSSLESS_BUFFER_PARAMETER),
        m_cfgDeviceMetaDataTable(cfgDb, CFG_DEVICE_METADATA_TABLE_NAME),
        m_applBufferPoolTable(applDb, APP_BUFFER_POOL_TABLE_NAME),
        m_applStateBufferPoolTable(applStateDb, APP_BUFFER_POOL_TABLE_NAME),
        m_applBufferProfileTable(applDb, APP_BUFFER_PROFILE_TABLE_NAME),
        m_applStateBufferProfileTable(applStateDb, APP_BUFFER_PROFILE_TABLE_NAME),
        m_applBufferObjectTables{ProducerStateTable(applDb, APP_BUFFER_PG_TABLE_NAME), ProducerStateTable(applDb, APP_BUFFER_QUEUE_TABLE_NAME)},
        m_applBufferProfileListTables{ProducerStateTable(applDb, APP_BUFFER_PORT_INGRESS_PROFILE_LIST_NAME), ProducerStateTable(applDb, APP_BUFFER_PORT_EGRESS_PROFILE_LIST_NAME)},
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME),
        m_stateBufferMaximumTable(stateDb, STATE_BUFFER_MAXIMUM_VALUE_TABLE),
        m_stateBufferPoolTable(stateDb, STATE_BUFFER_POOL_TABLE_NAME),
        m_stateBufferProfileTable(stateDb, STATE_BUFFER_PROFILE_TABLE_NAME),
        m_applPortTable(applDb, APP_PORT_TABLE_NAME),
        m_portInitDone(false),
        m_bufferPoolReady(false),
        m_bufferObjectsPending(true),
        m_bufferCompletelyInitialized(false),
        m_bufferProfileApplDbWritten(false),
        m_mmuSizeNumber(0),
        m_saiSyncPollIntervalSec(1)
{
    SWSS_LOG_ENTER();

    // Initialize the handler map
    initTableHandlerMap();
    parseGearboxInfo(gearboxInfo);
    if (nullptr != zeroProfilesInfo)
        m_zeroPoolAndProfileInfo = *zeroProfilesInfo;

    string platform = getenv("ASIC_VENDOR") ? getenv("ASIC_VENDOR") : "";
    if (platform == "")
    {
        SWSS_LOG_ERROR("Platform environment variable is not defined, buffermgrd won't start");
        return;
    }

    string headroomSha, bufferpoolSha;
    string headroomPluginName = "buffer_headroom_" + platform + ".lua";
    string bufferpoolPluginName = "buffer_pool_" + platform + ".lua";
    string checkHeadroomPluginName = "buffer_check_headroom_" + platform + ".lua";

    m_platform = platform;
    m_specific_platform = platform;     // default for non-Mellanox
    m_model_number = 0;

    // Retrieve the type of mellanox platform
    if (m_platform == "mellanox")
    {
        m_cfgDeviceMetaDataTable.hget("localhost", "platform", m_specific_platform);
        if (!m_specific_platform.empty())
        {
            // Mellanox model number follows "sn" in the platform name and is 4 digits long
            std::size_t sn_pos = m_specific_platform.find("sn");
            if (sn_pos != std::string::npos)
            {
                std::string model_number = m_specific_platform.substr (sn_pos + 2, 4);
                if (!model_number.empty())
                {
                    long modelNum = 0;
                    if (safeStringToLong(model_number, modelNum, 0, 9999))
                    {
                        m_model_number = static_cast<int>(modelNum);
                    }
                    else
                    {
                        SWSS_LOG_ERROR("Failed to parse Mellanox model number from '%s'", model_number.c_str());
                    }
                }
            }
        }
        if (!m_model_number) {
            SWSS_LOG_ERROR("Failed to retrieve Mellanox model number");
        }
    }

    try
    {
        string headroomLuaScript = swss::loadLuaScript(headroomPluginName);
        m_headroomSha = swss::loadRedisScript(applDb, headroomLuaScript);

        string bufferpoolLuaScript = swss::loadLuaScript(bufferpoolPluginName);
        m_bufferpoolSha = swss::loadRedisScript(applDb, bufferpoolLuaScript);

        string checkHeadroomLuaScript = swss::loadLuaScript(checkHeadroomPluginName);
        m_checkHeadroomSha = swss::loadRedisScript(applDb, checkHeadroomLuaScript);
    }
    catch (...)
    {
        if (platform != "mock_test")
        {
            SWSS_LOG_ERROR("Lua scripts for buffer calculation were not loaded successfully, buffermgrd won't start");
            return;
        }
    }

    // Init timer
    auto interv = timespec { .tv_sec = BUFFERMGR_TIMER_PERIOD, .tv_nsec = 0 };
    m_buffermgrPeriodtimer = new SelectableTimer(interv);
    auto executor = new ExecutableTimer(m_buffermgrPeriodtimer, this, "PORT_INIT_DONE_POLL_TIMER");
    Orch::addExecutor(executor);
    m_buffermgrPeriodtimer->start();

    // Try fetch mmu size from STATE_DB
    // - warm-reboot, the mmuSize should be in the STATE_DB,
    //   which is done by not removing it from STATE_DB before warm reboot
    // - warm-reboot for the first time or cold-reboot, the mmuSize is
    //   fetched from SAI and then pushed into STATE_DB by orchagent
    // This is to accelerate the process of inserting all the buffer pools
    // into APPL_DB when the system starts
    // In case that the mmuSize isn't available yet at time buffermgrd starts,
    // the buffer_pool_<vendor>.lua should try to fetch that from BUFFER_POOL
    m_stateBufferMaximumTable.hget("global", "mmu_size", m_mmuSize);
    if (!m_mmuSize.empty())
    {
        unsigned long mmuSizeNum = 0;
        if (safeStringToULong(m_mmuSize, mmuSizeNum))
        {
            m_mmuSizeNumber = mmuSizeNum;
        }
        else
        {
            SWSS_LOG_ERROR("Failed to parse mmu_size '%s', setting to 0", m_mmuSize.c_str());
            m_mmuSizeNumber = 0;
            m_mmuSize.clear();
        }
    }

    // Try fetch default dynamic_th from CONFIG_DB
    vector<string> keys;
    m_cfgDefaultLosslessBufferParam.getKeys(keys);
    if (!keys.empty())
    {
        m_cfgDefaultLosslessBufferParam.hget(keys[0], "default_dynamic_th", m_defaultThreshold);
    }

    // m_waitApplyAdditionalZeroProfiles represents for how long applying additional zero profiles will be deferred
    // after normal profiles and profiles for configured items have been applied
    // For warm reboot, it is not deferred as the additional zero profiles have been in the APPL_DB
    // In this case, they should be replayed as soon as possible
    // For fast/cold reboot and other initialization flow, it is defered for 30 seconds.
    // This is to accelerate the fast reboot converging time.
    if (WarmStart::isWarmStart())
    {
        m_waitApplyAdditionalZeroProfiles = 0;
        WarmStart::setWarmStartState("buffermgrd", WarmStart::INITIALIZED);
    }
    else
    {
        m_waitApplyAdditionalZeroProfiles = 3;
        WarmStart::setWarmStartState("buffermgrd", WarmStart::WSDISABLED);
    }
}

void BufferMgrDynamic::parseGearboxInfo(shared_ptr<vector<KeyOpFieldsValuesTuple>> gearboxInfo)
{
    if (nullptr == gearboxInfo)
    {
        m_supportGearbox = false;
    }
    else
    {
        string gearboxModel;
        for (auto &kfv : *gearboxInfo)
        {
            auto table = parseObjectNameFromKey(kfvKey(kfv), 0);
            auto key = parseObjectNameFromKey(kfvKey(kfv), 1);

            if (table.empty() || key.empty())
            {
                SWSS_LOG_ERROR("Invalid format of key %s for gearbox info, won't initialize it",
                               kfvKey(kfv).c_str());
                return;
            }

            if (table == STATE_PERIPHERAL_TABLE)
            {
                for (auto &fv: kfvFieldsValues(kfv))
                {
                    auto &field = fvField(fv);
                    auto &value = fvValue(fv);
                    SWSS_LOG_DEBUG("Processing table %s field:%s, value:%s", table.c_str(), field.c_str(), value.c_str());
                    if (field == "gearbox_delay")
                        m_gearboxDelay[key] = value;
                }
            }

            if (table == STATE_PORT_PERIPHERAL_TABLE)
            {
                if (key != "global")
                {
                    SWSS_LOG_ERROR("Port peripheral table: only global gearbox model is supported but got %s", key.c_str());
                    continue;
                }

                for (auto &fv: kfvFieldsValues(kfv))
                {
                    auto &field = fvField(fv);
                    auto &value = fvValue(fv);
                    SWSS_LOG_DEBUG("Processing table %s field:%s, value:%s", table.c_str(), field.c_str(), value.c_str());
                    if (fvField(fv) == "gearbox_model")
                        gearboxModel = fvValue(fv);
                }
            }
        }

        m_identifyGearboxDelay = m_gearboxDelay[gearboxModel];
        m_supportGearbox = false;
    }
}

/*
 * Zero buffer pools and profiles are introduced for reclaiming reserved buffer on unused ports.
 *
 * They are loaded into buffer manager through a json file provided from CLI on a per-platform basis
 * and will be applied to APPL_DB and STATE_DB on the ports once they are admin down.
 * They are loaded into APPL_DB in an order in which they occur in the json file, which means
 * it's vendor's responsibility to guarantee the order reflects the dependency among zero pools and profiles.
 * They are removed from APPL_DB once all ports are admin up.
 * The zero profiles are removed first and then the zero pools. This is to respect the dependency between them.
 *
 * The keys can be in format of:
 *  - <TABLE NAME>|<object name>: represents a zero buffer object, like a zero buffer pool or zero buffer profile
 *    All necessary fields of the object should be provided in the json file according to the type of the object.
 *    For the buffer profiles, if the buffer pools referenced are the normal pools, like {ingress|egress}_{lossless|lossy}_pool,
 *    the zero profile name will be stored in the referenced pool's "zero_profile_name" field for the purpose of
 *    - constructing the zero profile list or providing the zero profiles for PGs or queues
 *    - fetching the zero profile for a certain pool when applying the zero profile for configured items
 *
 *  - control_fields: represents the ids required for reclaiming unused buffers, including:
 *     - pgs_to_apply_zero_profile, represents the PGs on which the zero profiles will be applied for reclaiming unused buffers
 *       If it is not provided, zero profiles will be applied on all PGs.
 *     - ingress_zero_profile, represents the zero buffer profille which will be applied on PGs for reclaiming unused buffer.
 *       Typically, it is provided along with pgs_to_apply_zero_profile.
 *       In case pgs_to_apply_zero_profile is defined but ingress_zero_profile is not provided, the first zero profile on the ingress side in json file will be used.
 *     - queues_to_apply_zero_profile, represents the queues on which the zero profiles will be applied
 *       If it is not provided, zero profiles will be applied on all queues.
 *     - egress_zero_profile, represents the zero buffer profille which will be applied on queues for reclaiming unused buffer.
 *       Typically, it is provided along with queues_to_apply_zero_profile.
 *       In case queues_to_apply_zero_profile is defined but egress_zero_profile is not provided, the first zero profile on the egress side in json file will be used.
 *     - support_removing_buffer_items, represents whether the buffer items are supported to be removed.
 *    The number of queues and PGs are pushed into BUFFER_MAX_PARAM table in STATE_DB at the beginning of ports orchagent
 *    and will be learnt by buffer manager when it's starting.
 */
void BufferMgrDynamic::loadZeroPoolAndProfiles()
{
    for (auto &kfv : m_zeroPoolAndProfileInfo)
    {
        auto &table_key = kfvKey(kfv);

        if (table_key == "control_fields")
        {
            auto &fvs = kfvFieldsValues(kfv);
            for (auto &fv : fvs)
            {
                if (fvField(fv) == "pgs_to_apply_zero_profile")
                {
                    m_bufferObjectIdsToZero[BUFFER_PG] = fvValue(fv);
                }
                else if (fvField(fv) == "ingress_zero_profile")
                {
                    m_bufferZeroProfileName[BUFFER_PG] = fvValue(fv);
                }
                else if (fvField(fv) == "queues_to_apply_zero_profile")
                {
                    m_bufferObjectIdsToZero[BUFFER_QUEUE] = fvValue(fv);
                }
                else if (fvField(fv) == "egress_zero_profile")
                {
                    m_bufferZeroProfileName[BUFFER_QUEUE] = fvValue(fv);
                }
                else if (fvField(fv) == "support_removing_buffer_items")
                {
                    m_supportRemoving = (fvValue(fv) == "yes");
                }
            }

            continue;
        }

        auto const &table = parseObjectNameFromKey(table_key, 0);
        auto const &key = parseObjectNameFromKey(table_key, 1);

        if (table.empty() || key.empty())
        {
            SWSS_LOG_ERROR("Invalid format of key %s for zero profile info, won't initialize it",
                           kfvKey(kfv).c_str());
            return;
        }

        if (table == APP_BUFFER_POOL_TABLE_NAME)
        {
            m_applBufferPoolTable.set(key, kfvFieldsValues(kfv));
            m_stateBufferPoolTable.set(key, kfvFieldsValues(kfv));
            SWSS_LOG_NOTICE("Loaded zero buffer pool %s", key.c_str());
            m_zeroPoolNameSet.insert(key);
        }
        else if (table == APP_BUFFER_PROFILE_TABLE_NAME)
        {
            auto &fvs = kfvFieldsValues(kfv);
            bool poolNotFound = false;
            for (auto &fv : fvs)
            {
                if (fvField(fv) == "pool")
                {
                    const auto &poolName = fvValue(fv);
                    auto poolSearchRef = m_bufferPoolLookup.find(poolName);
                    if (poolSearchRef != m_bufferPoolLookup.end())
                    {
                        auto &poolObj = poolSearchRef->second;
                        if (poolObj.zero_profile_name.empty())
                        {
                            poolObj.zero_profile_name = key;
                            if (m_bufferZeroProfileName[poolObj.direction].empty())
                                m_bufferZeroProfileName[poolObj.direction] = poolObj.zero_profile_name;
                        }
                        else
                        {
                            SWSS_LOG_ERROR("Multiple zero profiles (%s, %s) detected for pool %s, takes the former and ignores the latter",
                                           poolObj.zero_profile_name.c_str(),
                                           key.c_str(),
                                           fvValue(fv).c_str());
                        }
                    }
                    else if (m_zeroPoolNameSet.find(poolName) == m_zeroPoolNameSet.end())
                    {
                        SWSS_LOG_WARN("Profile %s is not loaded as the referenced pool %s is not defined",
                                        key.c_str(),
                                        fvValue(fv).c_str());
                        poolNotFound = true;
                        break;
                    }

                    m_zeroProfiles.emplace_back(key, poolName);
                }
            }
            if (poolNotFound)
            {
                continue;
            }
            m_applBufferProfileTable.set(key, fvs);
            m_stateBufferProfileTable.set(key, fvs);
            SWSS_LOG_NOTICE("Loaded zero buffer profile %s", key.c_str());
        }
        else
        {
            SWSS_LOG_ERROR("Unknown keys %s with zero table name %s isn't loaded to APPL_DB", key.c_str(), table.c_str());
            continue;
        }
    }

    // Consistency checking
    // 1. For any buffer pool, if there is no zero profile provided, removing buffer items must be supported
    // because the reserved buffer will be reclaimed by removing buffer items
    // 2. If pgs_to_apply_zero_profile or queues_to_apply_zero_profile is provided, removing buffer items must be supported
    // because the PGs or queues that are not in the ID list will be removed
    bool noReclaiming = false;
    if (!m_supportRemoving)
    {
        for (auto &poolRef: m_bufferPoolLookup)
        {
            if (poolRef.second.zero_profile_name.empty())
            {
                // For any buffer pool, zero profile must be provided
                SWSS_LOG_ERROR("Zero profile is not provided for pool %s while removing buffer items is not supported, reserved buffer can not be reclaimed correctly", poolRef.first.c_str());
                noReclaiming = true;
            }
        }

        if (!m_bufferObjectIdsToZero[BUFFER_PG].empty() || !m_bufferObjectIdsToZero[BUFFER_QUEUE].empty())
        {
            SWSS_LOG_ERROR("Unified IDs of queues or priority groups specified while removing buffer items is not supported, reserved buffer can not be reclaimed correctly");
            noReclaiming = true;
        }
    }

    if (noReclaiming)
    {
        unloadZeroPoolAndProfiles();
        m_zeroPoolAndProfileInfo.clear();
    }
    else
    {
        m_zeroProfilesLoaded = true;
    }
}

void BufferMgrDynamic::unloadZeroPoolAndProfiles()
{
    for (auto &zeroProfile : m_zeroProfiles)
    {
        auto &zeroProfileName = zeroProfile.first;
        auto &poolReferenced = zeroProfile.second;

        auto poolSearchRef = m_bufferPoolLookup.find(poolReferenced);
        if (poolSearchRef != m_bufferPoolLookup.end())
        {
            auto &poolObj = poolSearchRef->second;
            poolObj.zero_profile_name.clear();
        }
        m_applBufferProfileTable.del(zeroProfileName);
        m_stateBufferProfileTable.del(zeroProfileName);
        SWSS_LOG_NOTICE("Unloaded zero buffer profile %s", zeroProfileName.c_str());
    }

    m_zeroProfiles.clear();

    for (auto &zeroPool : m_zeroPoolNameSet)
    {
        m_applBufferPoolTable.del(zeroPool);
        m_stateBufferPoolTable.del(zeroPool);
        SWSS_LOG_NOTICE("Unloaded zero buffer pool %s", zeroPool.c_str());
    }

    m_zeroPoolNameSet.clear();

    m_zeroProfilesLoaded = false;
}

void BufferMgrDynamic::initTableHandlerMap()
{
    m_bufferTableHandlerMap.insert(buffer_handler_pair(STATE_BUFFER_MAXIMUM_VALUE_TABLE, &BufferMgrDynamic::handleBufferMaxParam));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(CFG_DEFAULT_LOSSLESS_BUFFER_PARAMETER, &BufferMgrDynamic::handleDefaultLossLessBufferParam));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(CFG_BUFFER_POOL_TABLE_NAME, &BufferMgrDynamic::handleBufferPoolTable));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(CFG_BUFFER_PROFILE_TABLE_NAME, &BufferMgrDynamic::handleBufferProfileTable));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(CFG_BUFFER_QUEUE_TABLE_NAME, &BufferMgrDynamic::handleBufferQueueTable));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(CFG_BUFFER_PG_TABLE_NAME, &BufferMgrDynamic::handleBufferPgTable));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(CFG_BUFFER_PORT_INGRESS_PROFILE_LIST_NAME, &BufferMgrDynamic::handleBufferPortIngressProfileListTable));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(CFG_BUFFER_PORT_EGRESS_PROFILE_LIST_NAME, &BufferMgrDynamic::handleBufferPortEgressProfileListTable));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(CFG_PORT_TABLE_NAME, &BufferMgrDynamic::handlePortTable));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(CFG_PORT_CABLE_LEN_TABLE_NAME, &BufferMgrDynamic::handleCableLenTable));
    m_bufferTableHandlerMap.insert(buffer_handler_pair(STATE_PORT_TABLE_NAME, &BufferMgrDynamic::handlePortStateTable));

    m_bufferSingleItemHandlerMap.insert(buffer_single_item_handler_pair(CFG_BUFFER_QUEUE_TABLE_NAME, &BufferMgrDynamic::handleSingleBufferQueueEntry));
    m_bufferSingleItemHandlerMap.insert(buffer_single_item_handler_pair(CFG_BUFFER_PG_TABLE_NAME, &BufferMgrDynamic::handleSingleBufferPgEntry));
    m_bufferSingleItemHandlerMap.insert(buffer_single_item_handler_pair(CFG_BUFFER_PORT_INGRESS_PROFILE_LIST_NAME, &BufferMgrDynamic::handleSingleBufferPortIngressProfileListEntry));
    m_bufferSingleItemHandlerMap.insert(buffer_single_item_handler_pair(CFG_BUFFER_PORT_EGRESS_PROFILE_LIST_NAME, &BufferMgrDynamic::handleSingleBufferPortEgressProfileListEntry));
}

// APIs to handle variant kinds of keys

// Transform key from CONFIG_DB format to APPL_DB format
void BufferMgrDynamic::transformSeperator(string &name)
{
    size_t pos;
    while ((pos = name.find("|")) != string::npos)
        name.replace(pos, 1, ":");
}

// For string "TABLE_NAME|objectname", returns "objectname"
string BufferMgrDynamic::parseObjectNameFromKey(const string &key, size_t pos = 0)
{
    auto keys = tokenize(key, delimiter);
    if (pos >= keys.size())
    {
        SWSS_LOG_ERROR("Failed to fetch %zu-th sector of key %s", pos, key.c_str());
        return string();
    }
    return keys[pos];
}

string BufferMgrDynamic::getDynamicProfileName(const string &speed, const string &cable, const string &mtu, const string &threshold, const string &gearbox_model, long lane_count)
{
    string buffer_profile_key;

    if (mtu == DEFAULT_MTU_STR)
    {
        buffer_profile_key = "pg_lossless_" + speed + "_" + cable;
    }
    else
    {
        buffer_profile_key = "pg_lossless_" + speed + "_" + cable + "_mtu" + mtu;
    }

    if (threshold != m_defaultThreshold)
    {
        buffer_profile_key = buffer_profile_key + "_th" + threshold;
    }

    if (!gearbox_model.empty())
    {
        buffer_profile_key = buffer_profile_key + "_" + gearbox_model;
    }

    if (m_platform == "mellanox")
    {
        if ((lane_count == 8) &&
            (((m_model_number / 1000 == 4) && (speed != "400000")) ||
             ((m_model_number / 1000 == 5) && (speed !=