# 🛡️ PyFirewall

**PyFirewall** is a modular, user-space firewall engine built in Python for real-time packet inspection, rule-based filtering, and traffic analysis.

It is designed as an educational cybersecurity project that mirrors the architecture of real-world firewall and intrusion detection systems, while remaining lightweight and extensible.

---

## 🚀 Features

* 📡 Real-time packet sniffing using Scapy
* 🔍 Packet inspection (IP, port, protocol analysis)
* ⚙️ Rule-based filtering engine
* 🚨 Action handling (allow / block simulation / logging)
* 🧾 Persistent logging system
* 🧩 Modular architecture for easy extension

---

## 🏗️ Architecture

```
Packet Capture → Packet Inspection → Rule Engine → Action Engine → Logger
```

Each component is separated into its own module, making the system clean, scalable, and easy to upgrade.

---

## 📁 Project Structure

```
pyfirewall/
│
├── main.py          # Entry point
├── config.py        # Firewall rules
├── sniffer.py       # Packet capture
├── inspector.py     # Packet parsing
├── rules.py         # Rule matching engine
├── actions.py       # Action handler
├── logger.py        # Logging system
└── firewall.log     # Output log file
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/pyfirewall.git
cd pyfirewall
```

### 2. Install dependencies

```bash
pip install scapy
```

---

## ▶️ Usage

Run the firewall:

```bash
sudo python main.py
```

> ⚠️ Root/Administrator privileges are required for packet sniffing.

---

## 🧠 How It Works

1. **Sniffer** captures live network packets
2. **Inspector** extracts structured data (IP, ports, protocol)
3. **Rule Engine** checks packets against defined rules
4. **Action Engine** decides whether to allow or block (simulated)
5. **Logger** records all activity for analysis

---

## 📜 Example Rules

Defined in `config.py`:

```python
RULES = [
    {"action": "block", "src": "192.168.0.0"},
    {"action": "block", "dport": 80},
    {"action": "allow", "protocol": "TCP"},
]
```

---

## ⚠️ Limitations

* This is a **user-space firewall**, not a kernel-level firewall
* It **cannot truly drop packets** without OS-level integration
* Performance is not optimized for high-throughput environments

---

## 🔮 Future Improvements

* Integration with Linux Netfilter / NFQUEUE (real packet dropping)
* Intrusion Detection System (IDS) features

  * Port scan detection
  * SYN flood detection
* GUI dashboard (Qt or web-based)
* Remote monitoring & centralized logging
* Dynamic rule updates via API

---

## 🎯 Learning Objectives

This project helps you understand:

* Network packet structure (Layer 3 & 4)
* Traffic analysis and filtering
* Firewall architecture
* Intrusion detection concepts
* Modular system design

---

## 📌 Use Cases

* Cybersecurity learning & experimentation
* Packet analysis practice
* Foundation for IDS/IPS development
* Portfolio project for security roles

---

## 📄 License

This project is open-source and available under the MIT License.

---

## 🤝 Contributing

Contributions, improvements, and ideas are welcome.
Feel free to fork the project and submit a pull request.

---

## ⚡ Disclaimer

This project is for **educational purposes only**.
It should not be used as a production security solution.

---
