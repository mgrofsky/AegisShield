# 4. Use Case: Smart Manufacturing Systems

**Reference:**

AbuEmera, E. A., ElZouka, H. A., & Saad, A. A. (2022). **Security Framework for Identifying threats in Smart Manufacturing Systems Using STRIDE Approach.** 2022 2nd International Conference on Consumer Electronics and Computer Engineering (ICCECE), 605–612.

https://doi.org/10.1109/iccece54139.2022.9712770

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes a Data Flow Diagram (DFD) related to the smart manufacturing system). |
| **Application Type** | 🟢 Industrial Internet of Things (IIoT) |
| **Industry Sector** | 🟢 Manufacturing (The focus is on smart manufacturing systems). |
| **Data Sensitivity** | 🟡 High (This is inferred due to the handling of sensitive and critical operational data within the smart manufacturing environment). |
| **Internet Facing** | 🟡 Yes (The system includes connectivity with external networks, making it internet-facing). |
| **Number of Employees** | 🔴 Unknown (Not mentioned in the document). |
| **Compliance Requirements** | 🟡 IEC 62443 (Inferred due to relevance to cybersecurity requirements for industrial automation and control systems). |
| **Authentication Methods** | 🔴 None (The document discusses security vulnerabilities and threats but does not specify existing authentication methods). |
| **Database Technologies & Versions** | 🔴 Not specified. |
| **Operating Systems & Versions** | 🔴 Not specified. |
| **Programming Languages & Versions** | 🔴 Not specified. |
| **Web Frameworks & Versions** | 🔴 Not specified. |

---

## **Description of the Application/System Being Threat Modeled**

The system being threat-modeled is a **smart manufacturing system** that integrates **Cyber-Physical Systems (CPS) with the Internet of Things (IoT)** and utilizes **cloud computing services**. The architecture includes:

- **Control Center:** The central hub where **control commands** are issued through a **Wide Area Network (WAN) to Remote Terminal Units (RTUs)**. The Control Center includes a **Human-Machine Interface (HMI)** for **monitoring plant operations**, and a **Manufacturing Execution System (MES)** that **interfaces with Enterprise Resource Planning (ERP) systems** and manages **production workflows**. The MES relies on a **database** for storing **sensitive operational data**.
- **Remote SCADA System:** Each **RTU in the SCADA system** is responsible for **collecting data** and **status information** from **field devices**, processing this data, and sending it to the **gateway**. It also **receives control commands** from the Control Center and delivers them to the relevant **field devices**.
- **Field Devices:** These include **sensors, actuators, and Programmable Logic Controllers (PLCs)** that monitor and control **industrial processes**. The **PLCs are crucial** for executing **control logic** and **communicating data** back to the RTUs. These devices are **often reconfigurable** and can be accessed via **direct connections or LAN**.
- **Gateway:** The **gateway** is responsible for **transferring data** between the **SCADA system and cloud services**. It applies **encryption and decryption** processes to **secure the data** before transmitting it to the cloud. The gateway also **handles communication** between the system’s **field devices and cloud services**.
- **Cloud Services:** The **cloud services** manage **data storage, processing, and analytics**. This includes **brokers** for organizing data streams, **HTTP servers** for **user interaction and reporting**, and **cloud storage** for **long-term data retention**. The system uses **protocols like MQTT** for **data communication** and provides functionalities such as **event management** and **real-time data processing**.

The system operates within a **smart manufacturing environment**, where **advanced technologies** are leveraged to **monitor, control, and optimize industrial operations**. The integration of **CPS, IoT, and cloud computing** allows for **real-time data analytics, remote monitoring, and the automation of various industrial processes**, making it a **critical infrastructure in the manufacturing industry**.

---

## **Justification for Case Study 4: Smart Manufacturing Systems**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System Description or DFD** | 🟢 **5** | The paper provides a **comprehensive and accurate DFD**, clearly illustrating the **key components, data flows, and processes** of the smart manufacturing system. This **DFD enhances** the understanding of the system’s operation. |
| **Application Type** | 🟢 **5** | The application type is **explicitly identified** as an **Industrial Internet of Things (IIoT)** system, focusing on **smart manufacturing**. This is **stated clearly** in the paper. |
| **Industry Sector** | 🟢 **5** | The industry sector is **clearly stated** as **Manufacturing**, and the paper **focuses directly** on the **manufacturing environment**, which aligns with the rubric for **high relevance and explicit identification**. |
| **Data Sensitivity** | 🟡 **5** | **High data sensitivity inferred** due to the **handling of critical operational and sensitive manufacturing data**, including **workflows and operational information**, which can **severely impact factory performance**. |
| **Internet Facing** | 🟡 **5** | The system is **explicitly described** as **being internet-facing**, with **external connectivity via cloud services and external networks**, which is **critical for data exchange and remote management** in **smart manufacturing environments**. |
| **Compliance Requirements** | 🟡 **3** | Compliance with **IEC 62443** is **inferred** based on the **industry context**, but the **standard is not explicitly mentioned**. While the **context supports this inference**, it does **not fully meet the rubric requirement** for **explicit mention of compliance requirements**. |
| **Authentication Methods** | 🔴 **1** | **No explicit mention of authentication methods** is provided in the paper, despite a **discussion of security concerns**. This **absence represents a significant gap** in the **security framework**. |
| **Technical Details** | 🔴 **1** | **No specific technical details** regarding **databases, operating systems, or programming languages** are mentioned, which **leaves a gap** in understanding the **full technical infrastructure**. |
| **Threat Details** | 🟢 **5** | The **threats are well-defined** and **categorized using the STRIDE framework**, with **detailed explanations of risks and relevant mitigation strategies**, making the **threat analysis robust and comprehensive**. |

---

### **Total Score: 35 → 🟢 High Quality**

The total score for this case study is **35**, classifying it as **High Quality**.