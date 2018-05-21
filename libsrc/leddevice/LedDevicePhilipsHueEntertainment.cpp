#include "LedDevicePhilipsHueEntertainment.h"

// Qt includes
#include <QDebug>
#include <QDebug>

// Mbedtls
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/timing.h"
#include "mbedtls/config.h"

LedDevicePhilipsHueEntertainment::LedDevicePhilipsHueEntertainment(const std::string &output,
                                                                   const std::string &username,
                                                                   const std::string &clientkey,
                                                                   bool switchOffOnBlack, int transitiontime,
                                                                   unsigned int groupId,
                                                                   std::vector<unsigned int> lightIds)
        : LedDevicePhilipsHue(output, username, switchOffOnBlack, transitiontime, lightIds),
          clientkey(clientkey.c_str()),
          groupId(groupId) {

    saveStates(lightIds.size());
    switchOn(0);

    worker = new HueEntertainmentWorker(output, username, clientkey, &lights);
    worker->moveToThread(&workerThread);
    connect(&workerThread, SIGNAL(finished()), worker, SLOT(deleteLater()));
    connect(this, SIGNAL(establishConnection()), worker, SLOT(establishConnection()));
    workerThread.start();

    emit establishConnection();
}

LedDevicePhilipsHueEntertainment::~LedDevicePhilipsHueEntertainment() {
    workerThread.quit();
    workerThread.wait();
}

int LedDevicePhilipsHueEntertainment::write(const std::vector <ColorRgb> &ledValues) {
    unsigned int idx = 0;
    for (const ColorRgb& color : ledValues) {
        // Get lamp.
        PhilipsHueLight& lamp = lights.at(idx);
        // Scale colors from [0, 255] to [0, 1] and convert to xy space.
        CiColor xy = lamp.rgbToCiColor(color.red / 255.0f, color.green / 255.0f, color.blue / 255.0f);

        if(xy != lamp.color) {
            // Remember last color.
            lamp.color = xy;
        }

        // Next light id.
        idx++;
    }
    return 0;
}

int LedDevicePhilipsHueEntertainment::switchOff() {
    put(getGroupRoute(groupId), "{\"stream\":{\"active\":false}}");
    return 0;
}

void LedDevicePhilipsHueEntertainment::switchOn(unsigned int nLights) {
    put(getGroupRoute(groupId), "{\"stream\":{\"active\":true}}");
}

QString LedDevicePhilipsHueEntertainment::getGroupRoute(unsigned int groupId) {
    return QString("groups/%1").arg(groupId);
}

HueEntertainmentWorker::HueEntertainmentWorker(const std::string &output,
                                               const std::string &username,
                                               const std::string &clientkey,
                                               std::vector<PhilipsHueLight>* lights): output(output.c_str()),
                                                                                      username(username.c_str()),
                                                                                      clientkey(clientkey.c_str()),
                                                                                      lights(lights) {
}

void HueEntertainmentWorker::establishConnection() {
    int ret;
    const char *pers = "dtls_client";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_timing_delay_context timer;

    mbedtls_debug_set_threshold(1000);

    /*
    * -1. Load psk
    */
    QByteArray pskArray = clientkey.toUtf8();
    QByteArray pskRawArray = QByteArray::fromHex(pskArray);


    QByteArray pskIdArray = username.toUtf8();
    QByteArray pskIdRawArray = pskIdArray;

    /*
    * 0. Initialize the RNG and the session data
    */
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        qFatal("mbedtls_ctr_drbg_seed returned %d", ret);
    }

    /*
* 1. Start the connection
*/
    if ((ret = mbedtls_net_connect(&server_fd, output.toUtf8(),
                                   "2100", MBEDTLS_NET_PROTO_UDP)) != 0)
    {
        qFatal("mbedtls_net_connect FAILED %d", ret);
    }


    /*
 * 2. Setup stuff
 */
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        qFatal("mbedtls_ssl_config_defaults FAILED %d", ret);
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        qFatal("mbedtls_ssl_setup FAILED %d", ret);
    }

    if (0 != (ret = mbedtls_ssl_conf_psk(&conf, (const unsigned char*)pskRawArray.data(), pskRawArray.length() * sizeof(char),
                                         (const unsigned char *)pskIdRawArray.data(), pskIdRawArray.length() * sizeof(char))))
    {
        qFatal("mbedtls_ssl_conf_psk FAILED %d", ret);
    }

    int ciphers[2];
    ciphers[0] = MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256;
    ciphers[1] = 0;
    mbedtls_ssl_conf_ciphersuites(&conf, ciphers);

    if ((ret = mbedtls_ssl_set_hostname(&ssl, "Hue")) != 0)
    {
        qCritical("mbedtls_ssl_set_hostname FAILED", ret);
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd,
                        mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay,
                             mbedtls_timing_get_delay);

    /*
 * 4. Handshake
 */
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        mbedtls_ssl_conf_handshake_timeout(&conf, 400, 1000);
        do ret = mbedtls_ssl_handshake(&ssl);
        while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (ret == 0)
            break;
    }

    if (ret != 0)
    {
        qFatal("mbedtls_ssl_handshake FAILED %d", ret);
    }

    connected = true;

    char header[] = {
            'H', 'u', 'e', 'S', 't', 'r', 'e', 'a', 'm', //protocol
            0x01, 0x00, //version 1.0
            0x01, //sequence number 1
            0x00, 0x00, //reserved
            0x01, //color mode RGB
            0x00, //linear filter
    };

    while (true)
    {
        QByteArray Msg;

        Msg.append(header, sizeof(header));

        unsigned int idx = 0;
        for (const PhilipsHueLight& lamp : *lights) {
            quint64 R = lamp.color.x * 0xffff;
            quint64 G = lamp.color.y * 0xffff;
            quint64 B = lamp.color.bri * 0xffff;

            char light_stream[] = {
                    0x00, 0x00, (char)lamp.id, //light ID 1
                    static_cast<uint8_t>((R >> 8) & 0xff), static_cast<uint8_t>(R & 0xff),
                    static_cast<uint8_t>((G >> 8) & 0xff), static_cast<uint8_t>(G & 0xff),
                    static_cast<uint8_t>((B >> 8) & 0xff), static_cast<uint8_t>(B & 0xff)
            };

            Msg.append(light_stream, sizeof(light_stream));
            idx++;
        }

        int len = Msg.size();

        do ret = mbedtls_ssl_write(&ssl,  (unsigned char *) Msg.data(), len);
        while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (ret < 0)
        {
            break;
        }
    }
}

void HueEntertainmentWorker::sendValues(const std::vector <ColorRgb> &ledValues) {
    this->ledValues = ledValues;
}

HueEntertainmentWorker::~HueEntertainmentWorker() {
}