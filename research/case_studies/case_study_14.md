# 14. Use Case: Drone as a Service

**Reference:**

Salamh, F., Karabiyik, U., & Rogers, M. (2021). **A Constructive DIREST Security Threat Modeling for Drone as a Service.** Journal of Digital Forensics, Security and Law, 16(1).

https://doi.org/10.15394/jdfsl.2021.1695

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes Data Flow Diagrams (DFDs) that illustrate the architecture and data flows within the Drone as a Service (DaaS) system). |
| **Application Type** | 🟢 Drone as a Service (DaaS) Application. |
| **Industry Sector** | 🟢 Aerospace (with a focus on drones used for various applications including public safety, emergency response, and logistics). |
| **Data Sensitivity** | 🟢 High (Inferred due to the handling of sensitive operational data, flight logs, and potentially personal information collected by drones). |
| **Internet Facing** | 🟢 Yes (The system involves connectivity with external networks for data transmission, software updates, and remote operations). |
| **Number of Employees** | 🔴 Unknown (Not mentioned in the document). |
| **Compliance Requirements** | 🟡 FAA Regulations (Inferred due to the use of drones in public and private sectors, where compliance with aviation and cybersecurity standards is critical). |
| **Authentication Methods** | 🟢 Not specified (The document discusses security controls but does not detail specific authentication methods used). |
| **Database Technologies & Versions** | 🔴 Not specified. |
| **Operating Systems & Versions** | 🟡 Linux (mentioned in the context of the operating system used in drone firmware). |
| **Programming Languages and Versions Used** | 🔴 Not specified directly (but Python and C/C++ are commonly used in embedded systems and could be inferred based on standard practices). |
| **Web Frameworks and Versions Used** | 🔴 Not specified. |

---

## **Description of the Application/System Being Threat Modeled**

The system is a **Drone as a Service (DaaS) platform**, which **provides drone-based services** for various sectors including **emergency response, public safety, and logistics**. The **DaaS platform leverages Unmanned Aerial Vehicles (UAVs)** equipped with **advanced technologies such as sensors, cameras, GPS, and communication modules**.

### **Key Components:**

- **Unmanned Aerial Vehicles (UAVs):** These drones are the **primary devices used for various missions**, equipped with **embedded systems and firmware** to control their operations. They may perform tasks such as **surveillance, delivery, and data collection**.
- **Firmware and Embedded Systems:** The drones operate using **firmware that manages their hardware components** and ensures proper functionality. **Firmware security is critical**, as vulnerabilities in the software could expose the drones to **remote hijacking or data tampering**.
- **Ground Control Station (GCS):** This is the **central hub for managing and controlling the drones**. Operators can **monitor drone activities, issue commands, and manage data collected by the drones** through the **GCS**. It is connected to the **drones via secure communication channels**.
- **Cloud Services:** The **DaaS platform utilizes cloud-based services** for **data storage, processing, and analysis**. The cloud infrastructure supports **functions such as long-term data storage, large-scale analytics, and coordination between multiple drones and ground stations**.
- **Data Communication:** The system **relies on secure communication protocols** to **transmit data between drones, the GCS, and cloud services**. The **integrity and security of these communication channels are crucial** to prevent **interception and tampering of critical data**.

The **DaaS platform** is designed to **offer flexible and scalable drone services** across various sectors. It incorporates **multiple layers of technology**, including **UAV hardware, embedded systems, cloud infrastructure, and secure communication protocols**, to **deliver reliable and efficient services**.

---

## **Justification for Case Study 14: Drone as a Service**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System Description or DFD** | 🟢 **5** | The paper includes **detailed DFDs** that illustrate the **architecture and data flows** within the **Drone as a Service (DaaS) system**, clearly explaining **how the components interact**. |
| **Application Type** | 🟢 **5** | The system is **explicitly described as a Drone as a Service (DaaS) platform**, focusing on **unmanned aerial vehicles (UAVs) for public safety, logistics, and emergency response**. |
| **Industry Sector** | 🟢 **5** | The **industry sector is clearly identified as Aerospace**, with the paper **focusing on drones used in public safety, logistics, and emergency response contexts**. |
| **Data Sensitivity** | 🟢 **5** | **High data sensitivity is inferred** due to the **handling of critical operational data, flight logs, and potentially personal information collected by drones**. |
| **Internet Facing** | 🟢 **5** | The system is **internet-facing**, with **connectivity to external networks for data transmission, remote operations, and software updates**, as described in the paper. |
| **Compliance Requirements** | 🟡 **3** | **FAA Regulations are inferred** based on the **usage of drones in public and private sectors**, but the paper **does not explicitly mention compliance** with these or other **regulations**. |
| **Authentication Methods** | 🟢 **5** | **Not specified authentication methods are mentioned** in the paper, **leaving a significant gap** in the system's **security design**. |
| **Technical Details** | 🔴 **2** | The paper mentions **Linux for drone firmware**, but **details on other operating systems, programming languages, and frameworks** are **not explicitly covered**. |
| **Threat Details** | 🟢 **5** | The **threats are comprehensively defined using the STRIDE framework**, with **clear descriptions of risks like GPS spoofing, tampering with metadata, and DoS attacks**. |

---

### **Total Score: 37 → 🟢 High Quality**

The total score for this case study is **37**, classifying it as **High Quality**.