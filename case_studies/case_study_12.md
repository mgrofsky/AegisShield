# 12. Use Case: The Open Energy Monitor

**Reference:**

Salzillo, G., Rak, M., & Moretta, F. (2021). **Threat Modeling based Penetration Testing: The Open Energy Monitor Case study.** 13th International Conference on Security of Information and Networks, 1–8.

https://doi.org/10.1145/3433174.3433181

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes Data Flow Diagrams (DFDs) that illustrate the architecture and data flows within the Open Energy Monitor system, focusing on the MQTT protocol). |
| **Application Type** | 🟢 IoT Application (specifically focusing on home automation and energy monitoring systems). |
| **Industry Sector** | 🟢 Energy (The focus is on monitoring and managing energy consumption within a home automation context). |
| **Data Sensitivity** | 🟡 High (Inferred due to the handling of sensitive data related to energy usage, home automation, and potentially personal information). |
| **Internet Facing** | 🟡 Yes (The system includes connectivity with external networks, making it internet-facing). |
| **Number of Employees** | 🔴 Unknown (Not mentioned in the document). |
| **Compliance Requirements** | 🟡 ISO/IEC 30141 (Inferred as relevant due to the focus on IoT systems and reference to ISO IoT standards in the system modeling). |
| **Authentication Methods** | 🔴 Not specified (The document discusses the lack of security by default but does not detail specific authentication methods). |
| **Database Technologies & Versions** | 🟡 MySQL (Inferred based on the use of EmonCMS, which typically employs these databases for data storage and management). |
| **Operating Systems & Versions** | 🟡 Raspberry Pi OS (Raspbian) (used by the Raspberry Pi-based emonPi and emonBase units). |
| **Programming Languages & Versions** | 🟡 PHP (for EmonCMS), Python (Inferred based on the common practices for Raspberry Pi-based systems and the components used in the Open Energy Monitor system). |
| **Web Frameworks & Versions** | 🔴 Not specified. |

---

## **Description of the Application/System Being Threat Modeled**

The system being threat modeled is the **Open Energy Monitor (OEM) system**, an **open-source platform for home automation and energy monitoring**. The OEM system is designed to **monitor and control various home appliances and energy usage**, with a particular focus on the **MQTT protocol for communication between IoT devices**.

### **Key Components:**

- **emonPi and emonBase:** These are **base stations** that **collect data from other devices in the system**. They act as **central hubs for data collection, processing, and storage** within the OEM system.
- **EmonTh and emonTx:** These **modules measure environmental conditions** such as **temperature and humidity**, as well as **monitor power consumption and production within the home**.
- **WiFi MQTT Relay:** A **general-purpose relay controlled remotely via the MQTT protocol**, used to **manage various devices within the home automation system**.
- **MQTT Broker and Clients:** The **MQTT protocol facilitates communication between devices**. The **MQTT broker manages message distribution** among clients, and the system **relies heavily on this protocol for device communication**.
- **EmonCMS Web Application:** A **web-based interface** that allows **users to visualize the data collected by the OEM system**. It provides **insights into energy usage, environmental conditions, and system performance**, enabling users to **monitor and control their home automation setup**.

The system operates in a **connected environment**, where **data flows between sensors, base stations, and cloud storage**, enabling **remote monitoring and control of home energy systems**.

---

## **Justification for Case Study 12: The Open Energy Monitor**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System Description or DFD** | 🟢 **5** | The paper includes **detailed DFDs** that illustrate the **architecture and data flows** within the **Open Energy Monitor system**, focusing on the **MQTT protocol**. |
| **Application Type** | 🟢 **5** | The system is **explicitly described** as an **IoT Application**, focusing on **home automation and energy monitoring**. |
| **Industry Sector** | 🟢 **5** | The **industry sector is clearly identified** as **Energy**, with a focus on **monitoring and managing energy consumption in a home automation context**. |
| **Data Sensitivity** | 🟡 **5** | **High data sensitivity inferred** from the **handling of energy usage data, home automation, and potentially personal information**. |
| **Internet Facing** | 🟡 **5** | The system is **internet-facing**, as it **relies on external networks to facilitate data communication**. |
| **Compliance Requirements** | 🟡 **3** | **ISO/IEC 30141 is inferred** due to the **IoT system’s focus**, but **specific compliance standards are not explicitly discussed in the paper**. |
| **Authentication Methods** | 🔴 **1** | **No specific authentication methods are mentioned**, representing a **significant gap** in the **system's security architecture**. |
| **Technical Details** | 🟡 **3** | **MySQL, Raspberry Pi OS, and PHP are inferred or mentioned**, but **more comprehensive technical details such as other programming languages are not fully explored**. |
| **Threat Details** | 🟢 **5** | The **threats are well-defined using the STRIDE framework**, with **clear explanations of vulnerabilities and attack scenarios** in the **Open Energy Monitor system**. |

---

### **Total Score: 37 → 🟢 High Quality**

The total score for this case study is **37**, classifying it as **High Quality**.