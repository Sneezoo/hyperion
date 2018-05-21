#pragma once

#include "LedDevicePhilipsHue.h"

// Qt includes
#include <QObject>
#include <QThread>

// Mbedtls
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

class HueEntertainmentWorker: public QObject {
    Q_OBJECT;
    QThread workerThread;

public:
    HueEntertainmentWorker(const std::string& output, const std::string& username, const std::string& clientkey, std::vector<PhilipsHueLight>* lights);
    virtual ~HueEntertainmentWorker();
    std::vector<ColorRgb> ledValues;

public slots:
    void sendValues(const std::vector<ColorRgb> &ledValues);
    void establishConnection();

private:
    bool connected = false;
    /// Output
    QString output;
    /// Username
    QString username;
    /// Clientkey
    QString clientkey;
    /// Array to save the lamps.
    std::vector<PhilipsHueLight>* lights;

    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;

};

class LedDevicePhilipsHueEntertainment: public LedDevicePhilipsHue {
    Q_OBJECT;
    QThread workerThread;

public:
    LedDevicePhilipsHueEntertainment(const std::string& output, const std::string& username, const std::string& clientkey, bool switchOffOnBlack =
    false, int transitiontime = 1, unsigned int groupId = 0, std::vector<unsigned int> lightIds = std::vector<unsigned int>());

    ///
    /// Destructor of this device
    ///
    virtual ~LedDevicePhilipsHueEntertainment();

signals:
    void establishConnection();
    void sendValues(const std::vector<ColorRgb> &ledValues);

private:
    /// Clientkey
    QString clientkey;

    unsigned int groupId;

    HueEntertainmentWorker *worker;

    /// Sends the given led-color values via put request to the hue system
    ///
    /// @param ledValues The color-value per led
    ///
    /// @return Zero on success else negative
    ///
    virtual int write(const std::vector<ColorRgb> & ledValues);

    /// Restores the original state of the leds.
    virtual int switchOff();

    ///
    /// Switches the leds on.
    ///
    /// @param nLights the number of lights
    ///
    void switchOn(unsigned int nLights);

    QString getGroupRoute(unsigned int groupId);
};