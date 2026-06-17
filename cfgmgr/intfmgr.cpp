```cpp
#include <string.h>
#include "logger.h"
#include "dbconnector.h"
#include "producerstatetable.h"
#include "tokenize.h"
#include "ipprefix.h"
#include "intfmgr.h"
#include "exec.h"
#include "shellcmd.h"
#include "macaddress.h"
#include "warm_restart.h"
#include "subscriberstatetable.h"
#include <swss/redisutility.h>
#include "subintf.h"

using namespace std;
using namespace swss;

#define VLAN_PREFIX         "Vlan"
#define LAG_PREFIX          "PortChannel"
#define SUBINTF_LAG_PREFIX  "Po"
#define LOOPBACK_PREFIX     "Loopback"
#define VNET_PREFIX         "Vnet"
#define MTU_INHERITANCE     "0"
#define VRF_PREFIX          "Vrf"
#define VRF_MGMT            "mgmt"

#define LOOPBACK_DEFAULT_MTU_STR "65536"
#define DEFAULT_MTU_STR 9100
extern MacAddress gMacAddress;
extern MacAddress gSagMacAddress;

IntfMgr::IntfMgr(DBConnector *cfgDb, DBConnector *appDb, DBConnector *stateDb, const vector<string> &tableNames) :
        Orch(cfgDb, tableNames),
        m_cfgIntfTable(cfgDb, CFG_INTF_TABLE_NAME),
        m_cfgVlanIntfTable(cfgDb, CFG_VLAN_INTF_TABLE_NAME),
        m_cfgLagIntfTable(cfgDb, CFG_LAG_INTF_TABLE_NAME),
        m_cfgLoopbackIntfTable(cfgDb, CFG_LOOPBACK_INTERFACE_TABLE_NAME),
        m_cfgSagTable(cfgDb, CFG_SAG_TABLE_NAME),
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME),
        m_stateLagTable(stateDb, STATE_LAG_TABLE_NAME),
        m_stateVlanTable(stateDb, STATE_VLAN_TABLE_NAME),
        m_stateVrfTable(stateDb, STATE_VRF_TABLE_NAME),
        m_stateIntfTable(stateDb, STATE_INTERFACE_TABLE_NAME),
        m_appIntfTableProducer(appDb, APP_INTF_TABLE_NAME),
        m_appSagTableProducer(appDb, APP_SAG_TABLE_NAME),
        m_neighTable(appDb, APP_NEIGH_TABLE_NAME),
        m_appLagTable(appDb, APP_LAG_TABLE_NAME)
{
    auto subscriberStateTable = new swss::SubscriberStateTable(stateDb,
            STATE_PORT_TABLE_NAME, TableConsumable::DEFAULT_POP_BATCH_SIZE, 100);
    auto stateConsumer = new Consumer(subscriberStateTable, this, STATE_PORT_TABLE_NAME);
    Orch::addExecutor(stateConsumer);

    auto subscriberStateLagTable = new swss::SubscriberStateTable(stateDb,
            STATE_LAG_TABLE_NAME, TableConsumable::DEFAULT_POP_BATCH_SIZE, 200);
    auto stateLagConsumer = new Consumer(subscriberStateLagTable, this, STATE_LAG_TABLE_NAME);
    Orch::addExecutor(stateLagConsumer);

    if (!WarmStart::isWarmStart())
    {
        flushLoopbackIntfs();
        WarmStart::setWarmStartState("intfmgrd", WarmStart::WSDISABLED);
    }
    else
    {
        //Build the interface list to be replayed to Kernel
        buildIntfReplayList();
        if (m_pendingReplayIntfList.empty())
        {
            setWarmReplayDoneState();
        }
    }

    string swtype;
    Table cfgDeviceMetaDataTable(cfgDb, CFG_DEVICE_METADATA_TABLE_NAME);
    if(cfgDeviceMetaDataTable.hget("localhost", "switch_type", swtype))
    {
       mySwitchType = swtype;
    }
}

void IntfMgr::setIntfIp(const string &alias, const string &opCmd,
                        const IpPrefix &ipPrefix)
{
    stringstream    cmd;
    string          res;
    string          ipPrefixStr = ipPrefix.to_string();
    string          broadcastIpStr = ipPrefix.getBroadcastIp().to_string();
    int             prefixLen = ipPrefix.getMaskLength();

    if (ipPrefix.isV4())
    {
        (prefixLen < 31) ?
        (cmd << IP_CMD << " address " << shellquote(opCmd) << " " << shellquote(ipPrefixStr) << " broadcast " << shellquote(broadcastIpStr) <<" dev " << shellquote(alias)) :
        (cmd << IP_CMD << " address " << shellquote(opCmd) << " " << shellquote(ipPrefixStr) << " dev " << shellquote(alias));
    }
    else
    {
        string metric = "";
        // Kernel adds connected route with default metric of 256. But the metric is not
        // communicated to frr unless the ip address is added with explicit metric
        // In voq system, We need the static route to the remote neighbor and connected
        // route to have the same metric to enable BGP to choose paths from routes learned
        // via eBGP and iBGP over the internal inband port be part of same ecmp group.
        // For v4 both the metrics (connected and static) are default 0 so we do not need
        // to set the metric explicitly.
        if(mySwitchType == "voq")
        {
           metric = " metric 256";
        }

        (prefixLen < 127) ?
        (cmd << IP_CMD << " -6 address " << shellquote(opCmd) << " " << shellquote(ipPrefixStr) << " broadcast " << shellquote(broadcastIpStr) <<
         " dev " << shellquote(alias) << metric) :
        (cmd << IP_CMD << " -6 address " << shellquote(opCmd) << " " << shellquote(ipPrefixStr) << " dev " << shellquote(alias) << metric);
    }

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        if (!ipPrefix.isV4() && opCmd == "add")
        {
            SWSS_LOG_NOTICE("Failed to assign IPv6 on interface %s with return code %d, trying to enable IPv6 and retry", alias.c_str(), ret);
            if (!enableIpv6Flag(alias))
            {
                SWSS_LOG_ERROR("Failed to enable IPv6 on interface %s", alias.c_str());
                return;
            }
            ret = swss::exec(cmd.str(), res);
        }

        if (ret)
        {
            SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
        }
    }
}

void IntfMgr::setSagFdbEntry(const string &op, const string &alias, const string &mac_str)
{
    stringstream cmd;
    string res;

    if (op != "add" && op != "replace" && op != "del")
    {
        SWSS_LOG_ERROR("Invalid FDB operation '%s' for MAC %s on %s", op.c_str(), mac_str.c_str(), alias.c_str());
        return;
    }

    if (mac_str == gMacAddress.to_string())
    {
        // Don't add or del for global system MAC address
        return;
    }

    if (!alias.compare(0, strlen(VLAN_PREFIX), VLAN_PREFIX))
    {
        /* Ensure the key starts with "Vlan" otherwise ignore */
        int vlan_id;
        try
        {
            vlan_id = stoi(alias.substr(4));
        }
        catch (...)
        {
            SWSS_LOG_ERROR("Invalid Vlan alias format. Not a number after 'Vlan' prefix: %s", alias.c_str());
            return;
        }

        // cmd format: bridge fdb add 00:11:22:33:44:55 dev Bridge vlan 3 permanent
        cmd << "bridge fdb " << shellquote(op) << " " << shellquote(mac_str) << " dev Bridge vlan " << vlan_id << " permanent";

        int ret = swss::exec(cmd.str(), res);
        if (ret)
        {
            SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
        }
    }
}

void IntfMgr::setIntfMac(const string &alias, const string &mac_str)
{
    stringstream cmd;
    string res;

    cmd << IP_CMD << " link set " << shellquote(alias) << " address " << shellquote(mac_str);

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
    }
}

void IntfMgr::setIntfVrf(const string &alias, const string &vrfName)
{
    stringstream cmd;
    string res;

    if (!vrfName.empty())
    {
        cmd << IP_CMD << " link set " << shellquote(alias) << " master " << shellquote(vrfName);
    }
    else
    {
        cmd << IP_CMD << " link set " << shellquote(alias) << " nomaster";
    }
    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
    }
}

bool IntfMgr::setIntfMpls(const string &alias, const string& mpls)
{
    stringstream cmd;
    string res;

    if (mpls == "enable")
    {
        cmd << "sysctl -w net.mpls.conf." << shellquote(alias) << ".input=1";
    }
    else if ((mpls == "disable") || mpls.empty())
    {
        cmd << "sysctl -w net.mpls.conf." << shellquote(alias) << ".input=0";
    }
    else
    {
        SWSS_LOG_ERROR("MPLS state is invalid: \"%s\"", mpls.c_str());
        return false;
    }
    int ret = swss::exec(cmd.str(), res);
    // Don't return error unless MPLS is explicitly set
    if (ret && !mpls.empty())
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
    }
    return true;
}

void IntfMgr::setIntfState(const string &alias, bool isUp)
{
    stringstream cmd;
    string res;

    if (isUp)
    {
        cmd << IP_CMD << " link set " << shellquote(alias) << " up";
    }
    else
    {
        cmd << IP_CMD << " link set " << shellquote(alias) << " down";
    }

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
    }
}

void IntfMgr::addLoopbackIntf(const string &alias)
{
    stringstream cmd;
    string res;

    cmd << IP_CMD << " link add " << shellquote(alias) << " mtu " << LOOPBACK_DEFAULT_MTU_STR << " type dummy";
    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
    }
}

void IntfMgr::delLoopbackIntf(const string &alias)
{
    stringstream cmd;
    string res;

    cmd << IP_CMD << " link del " << shellquote(alias);
    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
    }
}

void IntfMgr::flushLoopbackIntfs()
{
    stringstream cmd;
    string res;

    cmd << IP_CMD << " link show type dummy | grep -o '" << LOOPBACK_PREFIX << "[^:]*'";

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_DEBUG("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
        return;
    }

    auto aliases = tokenize(res, '\n');
    for (string &alias : aliases)
    {
        SWSS_LOG_NOTICE("Remove loopback device %s", alias.c_str());
        delLoopbackIntf(alias);
    }
}

int IntfMgr::getIntfIpCount(const string &alias)
{
    stringstream cmd;
    string res;

    /* query ip address of the device with master name, it is much faster */
    // ip address show {{intf_name}}
    // $(ip link show {{intf_name}} | grep -o 'master [^\\s]*') ==> [master {{vrf_name}}]
    // | grep inet | grep -v 'inet6 fe80:' | wc -l
    cmd << IP_CMD << " address show " << shellquote(alias)
        << " $(" << IP_CMD << " link show " << shellquote(alias) << " | grep -o 'master [^\\s]*')"
        << " | grep inet | grep -v 'inet6 fe80:' | wc -l";

    int ret = swss::exec(cmd.str(), res);
    if (ret)
    {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
        return 0;
    }

    return std::stoi(res);
}

void IntfMgr::buildIntfReplayList(void)
{
    vector<string> intfList;

    m_cfgIntfTable.getKeys(intfList);
    std::copy( intfList.begin(), intfList.end(), std::inserter( m_pendingReplayIntfList, m_pendingReplayIntfList.end() ) );

    m_cfgLoopbackIntfTable.getKeys(intfList);
    std::copy( intfList.begin(), intfList.end(), std::inserter( m_pendingReplayIntfList, m_pendingReplayIntfList.end() ) );

    m_cfgVlanIntfTable.getKeys(intfList);
    std::copy( intfList.begin(), intfList.end(), std::inserter( m_pendingReplayIntfList, m_pendingReplayIntfList.end() ) );

    m_cfgLagIntfTable.getKeys(intfList);
    std::copy( intfList.begin(), intfList.end(), std::inserter( m_pendingReplayIntfList, m_pendingReplayIntfList.end() ) );

    SWSS_LOG_INFO("Found %d Total Intfs to be replayed", (int)m_pendingReplayIntfList.size() );
}

void IntfMgr::setWarmReplayDoneState()
{
    m_replayDone = true;
    WarmStart::setWarmStartState("intfmgrd", WarmStart::REPLAYED);
    // There is no operation to be performed for intfmgr reconcillation
    // Hence mark it reconciled right away
    WarmStart::setWarmStartState("intfmgrd", WarmStart::RECONCILED);
}

bool IntfMgr::isIntfCreated(const string &alias)
{
    vector<FieldValueTuple> temp;

    if (m_stateIntfTable.get(alias, temp))
    {
        SWSS_LOG_DEBUG("Intf %s is ready", alias.c_str());
        return true;
    }

    return false;
}

bool IntfMgr::isIntfChangeVrf(const string &alias, const string &vrfName)
{
    vector<FieldValueTuple> temp;

    if (m_stateIntfTable.get(alias, temp))
    {
        for (auto idx : temp)
        {
            const auto &field = fvField(idx);
            const auto &value = fvValue(idx);
            if (field == "vrf")
            {
                if (value == vrfName)
                    return false;
                else
                    return true;
            }
        }
    }

    return false;
}

void IntfMgr::addHostSubIntf(const string&intf, const string &subIntf, const string &vlan)
{
    stringstream cmd;
    string res;

    cmd << IP_CMD " link add link " << shellquote(intf) << " name " << shellquote(subIntf) << " type vlan id " << shellquote(vlan);
    EXEC_WITH_ERROR_THROW(cmd.str(), res);
}


std::string IntfMgr::getIntfAdminStatus(const string &alias)
{
    Table *portTable;
    string admin = "down";
    if (!alias.compare(0, strlen("Eth"), "Eth"))
    {
        portTable = &m_statePortTable;
    }
    else if (!alias.compare(0, strlen("Po"), "Po"))
    {
        portTable = &m_stateLagTable;
    }
    else
    {
        return admin;
    }

    vector<FieldValueTuple> temp;
    portTable->get(alias, temp);

    for (auto idx : temp)
    {
        const auto &field = fvField(idx);
        const auto &value = fvValue(idx);
        if (field == "admin_status")
        {
            admin = value;
        }
    }
    return admin;
}

std::string IntfMgr::getIntfMtu(const string &alias)
{
    Table *portTable;
    string mtu = "0";
    if (!alias.compare(0, strlen("Eth"), "Eth"))
    {
        portTable = &m_statePortTable;
    }
    else if (!alias.compare(0, strlen("Po"), "Po"))
    {
        portTable = &m_stateLagTable;
    }
    else
    {
        return mtu;
    }
    vector<FieldValueTuple> temp;
    portTable->get(alias, temp);
    for (auto idx : temp)
    {
        const auto &field = fvField(idx);
        const auto &value = fvValue(idx);
        if (field == "mtu")
        {
            mtu = value;
        }
    }
    if (mtu.empty())
    {
        mtu = std::to_string(DEFAULT_MTU_STR);
    }
    return mtu;
}

void IntfMgr::updateSubIntfMtu(const string &alias, const string &mtu)
{
    string intf;
    for (auto entry : m_subIntfList)
    {
        intf = entry.first;
        subIntf subIf(intf);
        if (subIf.parentIntf() == alias)
        {
            std::vector<FieldValueTuple> fvVector;

            string subif_config_mtu = m_subIntfList[intf].mtu;
            if (subif_config_mtu == MTU_INHERITANCE || subif_config_mtu.empty())
                subif_config_mtu = std::to_string(DEFAULT_MTU_STR);

            string subintf_mtu = setHostSubIntfMtu(intf, subif_config_mtu, mtu);

            FieldValueTuple fvTuple("mtu", subintf_mtu);
            fvVector.push_back(fvTuple);
            m_appIntfTableProducer.set(intf, fvVector);
        }
    }
}

std::string IntfMgr::setHostSubIntfMtu(const string &alias, const string &mtu, const string &parent_mtu)
{
    stringstream cmd;
    string res;

    string subifMtu = mtu;
    subIntf subIf(alias);

    int pmtu = (uint32_t)stoul(parent_mtu);
    int cmtu = (uint32_t)stoul(mtu);

    if (pmtu < cmtu)
    {
        subifMtu = parent_mtu;
    }
    SWSS_LOG_INFO("subintf %s active mtu: %s", alias.c_str(), subifMtu.c_str());
    cmd << IP_CMD " link set " << shellquote(alias) << " mtu " << shellquote(subifMtu);
    std::string cmd_str = cmd.str();
    int ret = swss::exec(cmd_str, res);

    if (ret && !isIntfStateOk(alias))
    {
        // Can happen when a SET notification on the PORT_TABLE in the State DB
        // followed by a new DEL notification that send by portmgrd
        SWSS_LOG_WARN("Setting mtu to %s netdev failed with cmd:%s, rc:%d, error:%s", alias.c_str(), cmd_str.c_str(), ret, res.c_str());
    }
    else if (ret)
    {
        throw runtime_error(cmd_str + " : " + res);
    }
    return subifMtu;
}

void IntfMgr::updateSubIntfAdminStatus(const string &alias, const string &admin)
{
    string intf;
    for (auto entry : m_subIntfList)
    {
        intf = entry.first;
        subIntf subIf(intf);
        if (subIf.parentIntf() == alias)
        {
            /*  Avoid duplicate interface admin UP event. */
            string curr_admin = m_subIntfList[intf].currAdminStatus;
            if (curr_admin == "up" && curr_admin == admin)
            {
                continue;
            }
            std::vector<FieldValueTuple> fvVector;
            string subintf_admin = setHostSubIntfAdminStatus(intf, m_subIntfList[intf].adminStatus, admin);
            m_subIntfList[intf].currAdminStatus = subintf_admin;
            FieldValueTuple fvTuple("admin_status", subintf_admin);
            fvVector.push_back(fvTuple);
            m_appIntfTableProducer.set(intf, fvVector);
        }
    }
}

bool IntfMgr::setIntfAdminStatus(const string &alias, const string &admin_status)
{
    stringstream cmd;
    string res, cmd_str;

    SWSS_LOG_INFO("intf %s admin_status: %s", alias.c_str(), admin_status.c_str());
    cmd << IP_CMD " link set " << shellquote(alias) << " " << shellquote(admin_status);
    cmd_str = cmd.str();
    int ret = swss::exec(cmd_str, res);
    if (ret && !isIntfStateOk(alias))
    {
        // Can happen when a DEL notification is sent by portmgrd immediately followed by a new SET notification
        SWSS_LOG_WARN("Setting admin_status to %s netdev failed with cmd:%s, rc:%d, error:%s",
                      alias.c_str(), cmd_str.c_str(), ret, res.c_str());
        return false;
    }
    else if (ret)
    {
        throw runtime_error(cmd_str + " : " + res);
    }
    return true;
}

std::string IntfMgr::setHostSubIntfAdminStatus(const string &alias, const string &admin_status, const string &parent_admin_status)
{
    if (parent_admin_status == "up" || admin_status == "down")
    {
        try
        {
            setIntfAdminStatus(alias, admin_status);
            return admin_status;
        }
        catch (const std::runtime_error &e)
        {
            SWSS_LOG_NOTICE("Set Host subinterface %s admin_status set failure %s failure. Runtime error: %s", alias.c_str(), admin_status.c_str(), e.what());
            throw;
        }
    }
    else
    {
        return "down";
    }
}

void IntfMgr::removeHostSubIntf(const string &subIntf)
{
    stringstream cmd;
    string res;

    cmd << IP_CMD " link del " << shellquote(subIntf);
    EXEC_WITH_ERROR_THROW(cmd.str(), res);
}

void IntfMgr::setSubIntfStateOk(const string &alias)
{
    vector<FieldValueTuple> fvTuples = {{"state", "ok"}};

    if (!alias.compare(0, strlen(SUBINTF_LAG_PREFIX), SUBINTF_LAG_PREFIX))
    {
        m_stateLagTable.set(alias, fvTuples);
    }
    else
    {
        // EthernetX using PORT_TABLE
        m_statePortTable.set(alias, fvTuples);
    }
}

void IntfMgr::removeSubIntfState(const string &alias)
{
    if (!alias.compare(0, strlen(SUBINTF_LAG_PREFIX), SUBINTF_LAG_PREFIX))
    {
        m_stateLagTable.del(alias);
    }
    else
    {
        // EthernetX using PORT_TABLE
        m_statePortTable.del(alias);
    }
}

bool IntfMgr::setIntfGratArp(const string &alias, const string &grat_arp)
{
    /*
     * Enable gratuitous ARP by accepting unsolicited ARP replies and untracked neighbor advertisements
     */
    stringstream cmd;
    string res;
    string garp_enabled;
    int rc;

    if (grat_arp == "enabled")
    {
        garp_enabled = "2";
    }
    else if (grat_arp == "disabled")
    {
        garp_enabled = "0";
    }
    else
    {
        SWSS_LOG_ERROR("GARP state is invalid: \"%s\"", grat_arp.c_str());
        return false;
    }

    cmd << ECHO_CMD << " " << shellquote(garp_enabled) << " > /proc/sys/net/ipv4/conf/" << shellquote(alias) << "/arp_accept";
    EXEC_WITH_ERROR_THROW(cmd.str(), res);
    SWSS_LOG_INFO("ARP accept set to \"%s\" on interface \"%s\"",  grat_arp.c_str(), alias.c_str());

    cmd.clear();
    cmd.str(std::string());

    // `accept_untracked_na` is not available in all kernels, so check for it before trying to set it
    cmd << "test -f /proc/sys/net/ipv6/conf/" << shellquote(alias) << "/accept_untracked_na";
    rc = swss::exec(cmd.str(), res);

    if (rc == 0) {
        cmd.clear();
        cmd.str(std::string());
        cmd << ECHO_CMD << " " << shellquote(garp_enabled) << " > /proc/sys/net/ipv6/conf/" << shellquote(alias) << "/accept_untracked_na";
        EXEC_WITH_ERROR_THROW(cmd.str(), res);
        SWSS_LOG_INFO("`accept_untracked_na` set to \"%s\" on interface \"%s\"",  grat_arp.c_str(), alias.c_str());
    }

    return true;
}

bool IntfMgr::setIntfProxyArp(const string &alias, const string &proxy_arp)
{
    stringstream cmd;
    string res;
    string proxy_arp_status;

    if (proxy_arp == "enabled")
    {
        proxy_arp_status = "1";
    }
    else if (proxy_arp == "disabled")
    {
        proxy_arp_status = "0";
    }
    else
    {
        SWSS_LOG_ERROR("Proxy ARP state is invalid: \"%s\"", proxy_arp.c_str());
        return false;
    }

    cmd << ECHO_CMD << " " << shellquote(proxy_arp_status) << " > /proc/sys/net/ipv4/conf/" << shellquote(alias) << "/proxy_arp_pvlan";
    EXEC_WITH_ERROR_THROW(cmd.str(), res);

    cmd.clear();
    cmd.str(std::string());

    cmd << ECHO_CMD << " " << shellquote(proxy_arp_status) << " > /proc/sys/net/ipv4/conf/" << shellquote(alias) << "/proxy_arp";
    EXEC_WITH_ERROR_THROW(cmd.str(), res);

    SWSS_LOG_INFO("Proxy ARP set to \"%s\" on interface \"%s\"", proxy_arp.c_str(), alias.c_str());
    return true;
}

bool IntfMgr::isIntfStateOk(const string &alias)
{
    vector<FieldValueTuple> temp;

    if (!alias.compare(0, strlen(VLAN_PREFIX), VLAN_PREFIX))
    {
        if (m_stateVlanTable.get(alias, temp))
        {
            SWSS_LOG_DEBUG("Vlan %s is ready", alias.c_str());
            return true;
        }
    }
    else if (!alias.compare(0, strlen(LAG_PREFIX), LAG_PREFIX))
    {
        if (m_stateLagTable.get(alias, temp))
        {
            SWSS_LOG_DEBUG("Lag %s is ready", alias.c_str());
            return true;
        }
    }
    else if (!alias.compare(0, strlen(VNET_PREFIX), VNET_PREFIX))
    {
        if (m_stateVrfTable.get(alias, temp))
        {
            SWSS_LOG_DEBUG("Vnet %s is ready", alias