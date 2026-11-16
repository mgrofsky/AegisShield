# 8. Use Case: Treatment of an Infotainment High Performance Computing HPC System

**Reference:**

Das, P., Asif, M. R. A., Jahan, S., Khondoker, R., Ahmed, K., & Bui, F. M. (2024). **STRIDE-Based Cybersecurity Threat Modeling, Risk Assessment and Treatment of an Infotainment High Performance Computing (HPC) System (2024010185).** Preprints.

https://doi.org/10.20944/preprints202401.0185.v1

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes a Data Flow Diagram (DFD) that illustrates the data flows within the Infotainment High-Performance Computing (HPC) system). |
| **Application Type** | 🟢 IoT Application (specifically an Infotainment High-Performance Computing (HPC) system for automotive vehicles). |
| **Industry Sector** | 🟢 Automotive (The focus is on in-vehicle infotainment systems within the automotive sector). |
| **Data Sensitivity** | 🟢 High (This is inferred due to the handling of sensitive user data, including personal information and vehicle data). |
| **Internet Facing** | 🟢 Yes (The system includes connectivity with external networks, including the internet, making it internet-facing). |
| **Number of Employees** | 🔴 Unknown (Not mentioned in the document). |
| **Compliance Requirements** | 🟡 ISO/SAE 21434 (Inferred as relevant to automotive cybersecurity, given the system's context). |
| **Authentication Methods** | 🔴 Not specified (The document discusses security vulnerabilities and threats but does not specify the existing authentication methods). |
| **Database Technologies & Versions** | 🔴 Not specified. |
| **Operating Systems & Versions** | 🔴 Not specified. |
| **Programming Languages & Versions** | 🔴 Not specified. |
| **Web Frameworks & Versions** | 🔴 Not specified. |

---

## **Description of the Application/System Being Threat Modeled**

The system under threat modeling is an **Infotainment High-Performance Computing (HPC) system** integrated into **modern automotive vehicles**. This system enhances the capabilities of **drivers and passengers** by providing **advanced features such as music, navigation, communication, and entertainment**. The **key components** of the system include:

- **On-Board Computer (OBC):** The **central processing unit** that **controls all operations** within the infotainment system, including **interactions with external networks and internal vehicle components**.
- **NFC, Bluetooth, Wi-Fi, and Cellular Network:** These modules provide **various forms of connectivity** for the infotainment system, enabling **data transfer, internet access, and communication with external devices**.
- **CAN Bus:** A **communication network** that allows the **on-board computer to interact with other electronic control units (ECUs) and vehicle subsystems**.
- **Touch Screen and Touch Screen Controller:** The **primary user interface**, allowing the **driver and passengers to interact with the infotainment system** through a **touchscreen display**.
- **Rear Screen and Video Buffer:** Provides **additional display options for passengers**, often used for **media playback**.
- **Car Audio System with Microphone and Speaker:** Facilitates **audio input and output** for **multimedia playback and hands-free communication**.
- **GPS and Temperature Sensor:** Provides **location-based services** and **environmental data** to **optimize vehicle operation and user experience**.

---

## **Justification for Case Study 8: Treatment of an Infotainment High Performance Computing (HPC) System**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System Description or DFD** | 🟢 **5** | The paper provides a **clear and comprehensive DFD** that illustrates **data flows** within the **Infotainment High-Performance Computing (HPC) system**, enhancing understanding of the **architecture**. |
| **Application Type** | 🟢 **5** | The system is **explicitly described as an IoT application**, focusing on the **infotainment HPC system** for **modern automotive vehicles**. |
| **Industry Sector** | 🟢 **5** | The **industry sector is clearly identified** as **Automotive**, with the paper **focusing on in-vehicle infotainment systems**. |
| **Data Sensitivity** | 🟢 **5** | **High data sensitivity inferred** due to the **handling of sensitive personal and vehicle data**, which is **central to the operation** of the infotainment system. |
| **Internet Facing** | 🟢 **5** | The system is **internet-facing**, with **clear connectivity** to **external networks such as Wi-Fi, NFC, Bluetooth, and cellular networks**, increasing its **exposure to threats**. |
| **Compliance Requirements** | 🟡 **3** | Compliance with **ISO/SAE 21434** is **inferred** based on the system's **context in automotive cybersecurity**, though it is **not explicitly mentioned in the paper**. |
| **Authentication Methods** | 🔴 **1** | **No authentication methods are explicitly mentioned** in the paper, representing a **significant omission** in the **security design**. |
| **Technical Details** | 🔴 **1** | **No specific technical details** regarding **databases, operating systems, or programming languages** are provided, which **limits the understanding** of the **technical infrastructure**. |
| **Threat Details** | 🟢 **5** | The **threats are well-defined** and **categorized using the STRIDE framework**, with **clear explanations of vulnerabilities and detailed descriptions of risks**, making the **analysis comprehensive**. |

---

### **Total Score: 35 → 🟢 High Quality**

The total score for this case study is **35**, classifying it as **High Quality**.