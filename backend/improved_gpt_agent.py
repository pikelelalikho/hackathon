# Optional local GPT analysis
def summarize_devices(devices):
    online = len([d for d in devices if d.get("status") == "Online"])
    offline = len([d for d in devices if d.get("status") == "Offline"])
    return f"GPT Analysis Summary:\nTotal Devices: {len(devices)}\nOnline: {online}\nOffline: {offline}"
