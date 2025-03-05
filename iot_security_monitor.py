# iot_security_monitor.py

class IoTSecurityMonitor:
    def __init__(self, devices):
        self.devices = devices

    def monitor_devices(self):
        for device in self.devices:
            if not device.is_secure():
                print(f"Alerta: Dispositivo {device.name} não seguro!")
