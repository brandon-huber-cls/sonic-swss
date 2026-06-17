```cpp
#include "macsecmgr.h"

#include <exec.h>
#include <shellcmd.h>
#include <swss/stringutility.h>
#include <swss/redisutility.h>
#include <boost/algorithm/string/predicate.hpp>

#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <string.h>
#include <error.h>
#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <algorithm>
#include <sstream>
#include <cctype>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>


using namespace std;
using namespace swss;

#define WPA_SUPPLICANT_CMD "/sbin/wpa_supplicant"
#define WPA_CLI_CMD        "/sbin/wpa_cli"
#define WPA_CONF           "/etc/wpa_supplicant.conf"
#define SOCK_DIR           "/var/run/"
#define MACSEC_KEY_FILE    "/etc/sonic/macsec_keys.dat"

constexpr std::uint64_t RETRY_TIME = 30;

/* retry interval, in millisecond */
constexpr std::uint64_t RETRY_INTERVAL = 100;

/*
 * The input cipher_str is the encrypted string which can be either of length 66 bytes or 130 bytes.
 *
 * 66 bytes of length, for 128-byte cipher suite
 *   - first 2 bytes of the string will be reserved for version/format identifier.
 *   - remaining 64 bytes will be encrypted string from the 32-byte plain text CAK input string.
 *
 * 130 bytes of length, for 256-byte cipher suite
 *   - first 2 bytes of the string will be reserved for version/format identifier.
 *   - remaining 128 bytes will be encrypted string from the 32 byte plain text CAK input string.
*/
constexpr std::size_t AES_LEN_128_BYTE = 66;
constexpr std::size_t AES_LEN_256_BYTE = 130;

static void lexical_convert(const std::string &policy_str, MACsecMgr::MACsecProfile::Policy & policy)
{
    SWSS_LOG_ENTER();

    if (boost::iequals(policy_str, "integrity_only"))
    {
        policy = MACsecMgr::MACsecProfile::Policy::INTEGRITY_ONLY;
    }
    else if (boost::iequals(policy_str, "security"))
    {
        policy = MACsecMgr::MACsecProfile::Policy::SECURITY;
    }
    else
    {
        throw std::invalid_argument("Invalid policy : " + policy_str);
    }
}

static void lexical_convert(const std::string &cipher_str, MACsecMgr::MACsecProfile::CipherSuite & cipher_suite)
{
    SWSS_LOG_ENTER();

    if (boost::iequals(cipher_str, "GCM-AES-128"))
    {
        cipher_suite = MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_128;
    }
    else if (boost::iequals(cipher_str, "GCM-AES-256"))
    {
        cipher_suite = MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_256;
    }
    else if (boost::iequals(cipher_str, "GCM-AES-XPN-128"))
    {
        cipher_suite = MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_XPN_128;
    }
    else if (boost::iequals(cipher_str, "GCM-AES-XPN-256"))
    {
        cipher_suite = MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_XPN_256;
    }
    else
    {
        throw std::invalid_argument("Invalid cipher_suite : " + cipher_str);
    }
}

/* Securely derives an encryption key from system-specific sources.
 * This function attempts to read a persistent key from MACSEC_KEY_FILE.
 * If the file doesn't exist, it generates a new random key and stores it securely.
 * 
 * Returns: A 32-byte key suitable for AES-256 encryption
 */
static std::vector<unsigned char> getDerivedKey()
{
    std::vector<unsigned char> key(32); // 256-bit key for AES-256
    
    std::ifstream keyFile(MACSEC_KEY_FILE, std::ios::binary);
    if (keyFile.good())
    {
        // Read existing key
        keyFile.read(reinterpret_cast<char*>(key.data()), key.size());
        if (keyFile.gcount() == static_cast<std::streamsize>(key.size()))
        {
            keyFile.close();
            return key;
        }
        keyFile.close();
    }
    
    // Generate new random key
    if (RAND_bytes(key.data(), key.size()) != 1)
    {
        throw std::runtime_error("Failed to generate random key: " + 
            std::string(ERR_error_string(ERR_get_error(), nullptr)));
    }
    
    // Store key securely with restricted permissions
    std::ofstream outFile(MACSEC_KEY_FILE, std::ios::binary | std::ios::trunc);
    if (!outFile)
    {
        SWSS_LOG_WARN("Cannot create key file, using ephemeral key");
        return key;
    }
    
    outFile.write(reinterpret_cast<const char*>(key.data()), key.size());
    outFile.close();
    
    // Set restrictive permissions (owner read/write only)
    chmod(MACSEC_KEY_FILE, S_IRUSR | S_IWUSR);
    
    return key;
}

/* Decodes an encrypted key using AES-256-CBC encryption.
 * 
 * The encrypted format consists of:
 *   - 2 bytes: version identifier (currently "01")
 *   - 16 bytes: initialization vector (IV)
 *   - N bytes: AES-256-CBC encrypted data
 * 
 * This replaces the insecure Type 7 XOR obfuscation with proper encryption.
 */
static std::string decodeKey(const std::string &cipher_str, const MACsecMgr::MACsecProfile::CipherSuite & cipher_suite)
{
    // Validate input length
    if ((cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_128) ||
        (cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_XPN_128))
    {
        if (cipher_str.length() != AES_LEN_128_BYTE)
            throw std::invalid_argument("Invalid length for cipher_string : " + cipher_str);
    }
    else if ((cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_256) ||
             (cipher_suite == MACsecMgr::MACsecProfile::CipherSuite::GCM_AES_XPN_256))
    {
        if (cipher_str.length() != AES_LEN_256_BYTE)
            throw std::invalid_argument("Invalid length for cipher_string : " + cipher_str);
    }

    // Check version identifier
    std::string version = cipher_str.substr(0, 2);
    if (version != "01")
    {
        throw std::invalid_argument("Unsupported encryption version: " + version);
    }

    // Extract IV and encrypted data
    std::string hex_data = cipher_str.substr(2);
    std::vector<unsigned char> encrypted_data;
    
    for (size_t i = 0; i < hex_data.length(); i += 2)
    {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex_data.substr(i, 2);
        ss >> byte;
        encrypted_data.push_back(static_cast<unsigned char>(byte));
    }

    if (encrypted_data.size() < 16)
    {
        throw std::invalid_argument("Invalid encrypted data: too short");
    }

    // Extract IV (first 16 bytes)
    std::vector<unsigned char> iv(encrypted_data.begin(), encrypted_data.begin() + 16);
    std::vector<unsigned char> ciphertext(encrypted_data.begin() + 16, encrypted_data.end());

    // Get encryption key
    std::vector<unsigned char> key = getDerivedKey();

    // Decrypt using AES-256-CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        throw std::runtime_error("Failed to create cipher context");
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

template<class T>
static bool get_value(
    const MACsecMgr::TaskArgs & ta,
    const std::string & field,
    T & value)
{
    SWSS_LOG_ENTER();

    auto value_opt = swss::fvsGetValue(ta, field, true);
    if (!value_opt)
    {
        SWSS_LOG_DEBUG("Cannot find field : %s", field.c_str());
        return false;
    }

    try
    {
        lexical_convert(*value_opt, value);
    }
    catch(const boost::bad_lexical_cast &e)
    {
        SWSS_LOG_ERROR("Cannot convert value(%s) in field(%s)", value_opt->c_str(), field.c_str());
        return false;
    }

    return true;
}

static void wpa_cli_commands(std::ostringstream & ostream)
{
    // Intentionally emtpy function to adapt
    // the recursively calling of wpa_cli_commands
}

template<typename T, typename...Args>
static void wpa_cli_commands(
    std::ostringstream & ostream,
    T && t,
    Args && ... args)
{
    ostream << " " << shellquote(std::to_string(t));
    wpa_cli_commands(ostream, args...);
}

template<typename...Args>
static void wpa_cli_commands(
    std::ostringstream & ostream,
    const std::string & t,
    Args && ... args)
{
    ostream << " " << shellquote(t);
    wpa_cli_commands(ostream, args...);
}

template<typename...Args>
static void wpa_cli_commands(
    std::ostringstream & ostream,
    const std::string & sock,
    const std::string & port_name,
    const std::string & network_id,
    Args && ... args)
{
    ostream << shellquote(WPA_CLI_CMD);
    wpa_cli_commands(ostream, "-g", sock);
    if (!port_name.empty())
    {
        ostream << " " << shellquote("IFNAME=" + port_name);
    }
    if (!network_id.empty())
    {
        wpa_cli_commands(ostream, "set_network", network_id);
    }
    wpa_cli_commands(ostream, args...);
}

template<typename...Args>
static std::string wpa_cli_exec(
    const std::string & sock,
    const std::string & port_name,
    const std::string & network_id,
    Args && ... args)
{
    std::ostringstream ostream;
    std::string res;
    wpa_cli_commands(
        ostream,
        sock,
        port_name,
        network_id,
        std::forward<Args>(args)...);
    EXEC_WITH_ERROR_THROW(ostream.str(), res);
    return res;
}

template<typename...Args>
static void wpa_cli_exec_and_check(
    const std::string & sock,
    const std::string & port_name,
    const std::string & network_id,
    Args && ... args)
{
    std::string res = wpa_cli_exec(
        sock,
        port_name,
        network_id,
        std::forward<Args>(args)...);
    if (res.find("OK") != 0)
    {
        std::ostringstream ostream;
        wpa_cli_commands(
            ostream,
            sock,
            port_name,
            network_id,
            std::forward<Args>(args)...);
        throw std::runtime_error(
            "Wpa_cli command : " + ostream.str() + " -> " +res);
    }
}

MACsecMgr::MACsecMgr(
    DBConnector *cfgDb,
    DBConnector *stateDb,
    const vector<std::string> &tables) :
        Orch(cfgDb, tables),
        m_statePortTable(stateDb, STATE_PORT_TABLE_NAME)
{
}

MACsecMgr::~MACsecMgr()
{
    // Disable MACsec for all ports
    while (!m_macsec_ports.empty())
    {
        auto port = m_macsec_ports.begin();
        const TaskArgs temp;
        disableMACsec(port->first, temp);
    }
}

void MACsecMgr::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    using TaskType = std::tuple<const std::string,const std::string>;
    using TaskFunc = task_process_status (MACsecMgr::*)(const std::string &, const TaskArgs &);
    const static std::map<TaskType, TaskFunc > TaskMap = {
        { { CFG_MACSEC_PROFILE_TABLE_NAME, SET_COMMAND }, &MACsecMgr::loadProfile},
        { { CFG_MACSEC_PROFILE_TABLE_NAME, DEL_COMMAND }, &MACsecMgr::removeProfile},
        { { CFG_PORT_TABLE_NAME, SET_COMMAND }, &MACsecMgr::enableMACsec},
        { { CFG_PORT_TABLE_NAME, DEL_COMMAND }, &MACsecMgr::disableMACsec},
    };

    const std::string & table_name = consumer.getTableName();
    auto itr = consumer.m_toSync.begin();
    while (itr != consumer.m_toSync.end())
    {
        task_process_status task_done = task_failed;
        auto & message = itr->second;
        const std::string & op = kfvOp(message);

        auto task = TaskMap.find(std::make_tuple(table_name, op));
        if (task != TaskMap.end())
        {
            task_done = (this->*task->second)(
                kfvKey(message),
                kfvFieldsValues(message));
        }
        else
        {
            SWSS_LOG_ERROR(
                "Unknown task : %s - %s",
                table_name.c_str(),
                op.c_str());
        }

        if (task_done == task_need_retry)
        {
            SWSS_LOG_DEBUG(
                "Task %s - %s need retry",
                table_name.c_str(),
                op.c_str());
            ++itr;
        }
        else
        {
            if (task_done != task_success)
            {
                SWSS_LOG_WARN("Task %s - %s fail",
                    table_name.c_str(),
                    op.c_str());
            }
            else
            {
                SWSS_LOG_DEBUG(
                    "Task %s - %s success",
                    table_name.c_str(),
                    op.c_str());
            }

            itr = consumer.m_toSync.erase(itr);
        }
    }
}

#define GetValue(args, name) (get_value(args, #name, name))

bool MACsecMgr::MACsecProfile::update(const TaskArgs & ta)
{
    SWSS_LOG_ENTER();

    // The following fields are optional
    if (GetValue(ta, fallback_cak) && !GetValue(ta, fallback_ckn))
    {
        return false;
    }
    if (!GetValue(ta, enable_replay_protect))
    {
        enable_replay_protect = false;
    }
    if (!GetValue(ta, replay_window))
    {
        replay_window = 0;
    }
    if (!GetValue(ta, send_sci))
    {
        send_sci = true;
    }
    if (!GetValue(ta, rekey_period))
    {
        rekey_period = 0;
    }
    if (!GetValue(ta, priority))
    {
        priority = 255;
    }
    if (!GetValue(ta, policy))
    {
        policy = Policy::SECURITY;
    }

    // The following fields are necessary
    return GetValue(ta, cipher_suite)
        && GetValue(ta, primary_cak)
        && GetValue(ta, primary_ckn);
}

task_process_status MACsecMgr::loadProfile(
    const std::string & profile_name,
    const TaskArgs & profile_attr)
{
    SWSS_LOG_ENTER();

    auto profile = m_profiles.emplace(
        std::piecewise_construct,
        std::make_tuple(profile_name),
        std::make_tuple());
    try
    {
        if (profile.first->second.update(profile_attr))
        {
            SWSS_LOG_NOTICE(
                "The MACsec profile '%s' is loaded",
                profile_name.c_str());
        }
        // If the profile has been used
        if (profile.second)
        {
            for (auto & port : m_macsec_ports)
            {
                if (port.second.profile_name == profile_name)
                {
                    // Hot update
                    SWSS_LOG_DEBUG("Hot update");
                }
            }
        }
        return task_success;
    }
    catch(const std::invalid_argument & e)
    {
        SWSS_LOG_WARN("%s", e.what());
        return task_failed;
    }
}

task_process_status MACsecMgr::removeProfile(
    const std::string & profile_name,
    const TaskArgs & profile_attr)
{
    SWSS_LOG_ENTER();

    auto profile = m_profiles.find(profile_name);
    if (profile == m_profiles.end())
    {
        SWSS_LOG_WARN(
            "The MACsec profile '%s' wasn't loaded",
            profile_name.c_str());
        return task_invalid_entry;
    }

    // The MACsec profile cannot be removed if it is occupied
    auto port = std::find_if(
        m_macsec_ports.begin(),
        m_macsec_ports.end(),
        [&](const decltype(m_macsec_ports)::value_type & pair)
        {
            return pair.second.profile_name == profile_name;
        });
    if (port != m_macsec_ports.end())
    {
        // This MACsec profile is occupied by some ports
        // remove it after all ports disable MACsec
        SWSS_LOG_DEBUG(
            "The MACsec profile '%s' is used by the port '%s'",
            profile_name.c_str(),
            port->first.c_str());
        return task_need_retry;
    }
    SWSS_LOG_NOTICE("The MACsec profile '%s' is removed", profile_name.c_str());
    m_profiles.erase(profile);
    return task_success;
}

task_process_status MACsecMgr::enableMACsec(
    const std::string & port_name,
    const TaskArgs & port_attr)
{
    SWSS_LOG_ENTER();

    std::string profile_name;
    if (!get_value(port_attr, "macsec", profile_name)
        || profile_name.empty())
    {
        SWSS_LOG_DEBUG("MACsec field of port '%s' is empty", port_name.c_str());
        return disableMACsec(port_name, port_attr);
    }

    // If the MACsec profile is ready
    auto itr = m_profiles.find(profile_name);
    if (itr == m_profiles.end())
    {
        SWSS_LOG_DEBUG(
            "The MACsec profile '%s' for the port '%s' isn't ready",
            profile_name.c_str(),
            port_name.c_str());
        return task_need_retry;
    }
    auto & profile = itr->second;

    // If the port is ready
    if (!isPortStateOk(port_name))
    {
        SWSS_LOG_DEBUG("The port '%s' isn't ready", port_name.c_str());
        return task_need_retry;
    }

    // Handle existing macsec profile
    auto port_itr = m_macsec_ports.find(port_name);
    if (port_itr != m_macsec_ports.end())
    {
        if (port_itr->second.profile_name == profile_name)
        {
            SWSS_LOG_NOTICE(
                "The MACsec profile '%s' on the port '%s' has been loaded",
                profile_name.c_str(),
                port_name.c_str());
            return task_success;
        }
        else
        {
            SWSS_LOG_NOTICE(
                "The MACsec profile '%s' on the port '%s' "
                "will be replaced by the MACsec profile '%s'",
                port_itr->second.profile_name.c_str(),
                port_name.c_str(),
                profile_name.c_str());
            auto result = disableMACsec(port_name, port_attr);
            if (result != task_success)
            {
                return result;
            }
        }
    }
    // Create MKA Session object
    auto port = m_macsec_ports.emplace(
        std::piecewise_construct,
        std::make_tuple(port_name),
        std::make_tuple());
    auto & session = port.first->second;
    session.profile_name = profile_name;
    ostringstream ostream;
    ostream << SOCK_DIR << port_name;
    session.sock = ostream.str();
    session.wpa_supplicant_pid = startWPASupplicant(session.sock);
    if (session.wpa_supplicant_pid < 0)
    {
        SWSS_LOG_WARN("Cannot start the wpa_supplicant of the port '%s' : %s",
            port_name.c_str(),
            strerror(errno));
        m_macsec_ports.erase(port.first);
        return task_need_retry;
    }
    else if (session.wpa_supplicant_pid == 0)
    {
        SWSS_LOG_WARN("Cannot start the wpa_supplicant of the port '%s' : %s",
        port_name.c_str(),
        strerror(errno));
        m_macsec_ports.erase(port.first);
        return task_failed;
    }

    // Enable MACsec
    if (!configureMACsec(port_name, session, profile))
    {
        SWSS_LOG_WARN("The MACsec profile '%s' on the port '%s' loading fail",
            profile_name.c_str(),
            port_name.c_str());
        return disableMACsec(port_name, port_attr);
    }
    SWSS_LOG_NOTICE("The MACsec profile '%s' on the port '%s' loading success",
        profile_name.c_str(),
        port_name.c_str());
    return task_success;
}

task_process_status MACsecMgr::disableMACsec(
    const std::string & port_name,
    const TaskArgs & port_attr)
{
    SWSS_LOG_ENTER();

    auto itr = m_macsec_ports.find(port_name);
    if (itr == m_macsec_ports.end())
    {
        SWSS_LOG_NOTICE("The MACsec was not enabled on the port '%s'",
            port_name.c_str());
        return task_success;
    }
    auto & session = itr->second;
    task_process_status ret = task_success;
    if (!unconfigureMACsec(port_name, session))
    {
        SWSS_LOG_WARN(
            "Cannot stop MKA session on the port '%s'",
            port_name.c_str());
        ret = task_failed;
    }
    if (!stopWPASupplicant(session.wpa_supplicant_pid))
    {
        SWSS_LOG_WARN(
            "Cannot stop WPA_SUPPLICANT process of the port '%s'",
            port_name.c_str());
        ret = task_failed;
    }
    if (ret == task_success)
    {
        SWSS_LOG_NOTICE("The MACsec profile '%s' on the port '%s' is removed",
            itr->second.profile_name.c_str(),
            port_name.c_str());
    }
    m_macsec_ports.erase(itr);
    return ret;
}

bool MACsecMgr::isPortStateOk(const std::string & port_name)
{
    SWSS_LOG_ENTER();

    std::vector<FieldValueTuple> temp;
    std::string state;
    std::string oper_status;

    if (m_statePortTable.get(port_name, temp)
        && get_value(temp, "state", state)
        && state == "ok"
        && get_value(temp, "netdev_oper_status", oper_status)
        && oper_status == "up")
    {
        SWSS_LOG_DEBUG("Port '%s' is ready", port_name.c_str());
        return true;
    }
    SWSS_LOG_DEBUG("Port '%s' is not ready", port_name.c_str());
    return false;
}

pid_t MACsecMgr::startWPASupplicant(const std::string & sock) const
{
    SWSS_LOG_ENTER();

    pid_t wpa_supplicant_pid = fork();
    if (wpa_supplicant_pid == 0)
    {
        exit(execl(
            WPA_SUPPLICANT_CMD,
            WPA_SUPPLICANT_CMD,
            "-s",
            "-D", "macsec_sonic",
            "-g", sock.c_str(),
            NULL));
    }
    else if (wpa_supplicant_pid > 0)
    {
        // Wait wpa_supplicant ready
        bool wpa_supplicant_loading = false;
        auto retry_time = RETRY_TIME;
        while(!wpa_supplicant_loading && retry_time > 0)
        {
            try
            {
                wpa_cli_exec(sock, "", "", "status");
                wpa_supplicant_loading = true;
            }
            catch(const std::runtime_error&)
            {
                retry_time--;
                std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_INTERVAL));
            }
        }
        if (wpa_supplicant_loading)
        {
            SWSS_LOG_DEBUG("Start wpa_supplicant success");
        }
        else
        {
            stopWPASupplicant(wpa_supplicant_pid);
            wpa_supplicant_pid = 0;
            SWSS_LOG_WARN("Cannot connect to wpa_supplicant.");
        }
    }
    return wpa_supplicant_pid;
}

bool MACsecMgr::stopWPASupplicant(pid_t pid) const
{
    SWSS_LOG_ENTER();

    if(kill(pid, SIGINT) != 0)
    {
        SWSS_LOG_WARN("Cannot stop wpa_supplicant(%d)", pid);
        return false;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    SWSS_LOG_DEBUG(
        "Stop wpa_supplicant(%d) with return value (%d)",
        pid,
        status);
    return status == 0;
}

bool MACsecMgr::configureMACsec(
    const std::string & port_name,
    const MKASession & session,
    const MACsecProfile & profile) const
{
    SWSS_LOG_ENTER();

    try
    {
        wpa_cli_exec_and_check(
            session.sock,
            "",
            "",
            "interface_add",
            port_name,
            WPA_CONF,
            "macsec_sonic");

        const std::string res = wpa