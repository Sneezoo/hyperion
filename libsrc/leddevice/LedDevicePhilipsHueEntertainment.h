#pragma once

#include "LedDevicePhilipsHue.h"

// Qt includes
#include <QObject>
#include <QThread>

// Mbedtls
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

class HueEntertainmentWorker: public QThread {
    Q_OBJECT;

public:
    HueEntertainmentWorker(const std::string& output, const std::string& username, const std::string& clientkey, std::vector<PhilipsHueLight>* lights);

    void run();

private:
    /// Output
    QString output;
    /// Username
    QString username;
    /// Clientkey
    QString clientkey;
    /// Array to save the lamps.
    std::vector<PhilipsHueLight>* lights;
};

class LedDevicePhilipsHueEntertainment: public LedDevicePhilipsHue {
    Q_OBJECT;

public:
    LedDevicePhilipsHueEntertainment(const std::string& output, const std::string& username, const std::string& clientkey, bool switchOffOnBlack =
    false, int transitiontime = 1, unsigned int groupId = 0, std::vector<unsigned int> lightIds = std::vector<unsigned int>());

    ///
    /// Destructor of this device
    ///
    virtual ~LedDevicePhilipsHueEntertainment();

signals:
    void establishConnection();

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