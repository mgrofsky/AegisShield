# 15. Use Case: Cyber Physical Systems - Window Cleaning Business

**Reference:**

Brown, S., Fox, S., Hewage, C., & Khan, I. (2022). **Threat Modelling of Cyber Physical Systems: A Real Case Study Based on Window Cleaning Business.** SN Computer Science, 3(2), 139.

https://doi.org/10.1007/s42979-022-01021-3

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes Data Flow Diagrams (DFDs) illustrating the architecture and data flows within the Cyber-Physical System (CPS) used for the window cleaning operation). |
| **Application Type** | 🟢 Cyber-Physical System (CPS) Application. |
| **Industry Sector** | 🟢 Commercial Services (specifically focusing on window cleaning operations using advanced IoT and cloud technologies). |
| **Data Sensitivity** | 🟢 High (Inferred due to the handling of sensitive operational data, including GPS tracking, real-time IoT data, and business intelligence related to resource usage). |
| **Internet Facing** | 🟢 Yes (The system includes connectivity with external networks, such as cloud services, making it internet-facing). |
| **Number of Employees** | 🔴 Unknown (Not mentioned in the document). |
| **Compliance Requirements** | 🟡 None. |
| **Authentication Methods** | 🟢 Firebase Authentication, API Key (mentioned in the context of securing access to the Firestore database and mobile applications). |
| **Database Technologies and Versions** | 🟢 Google Firestore (a real-time NoSQL database used for data storage in the cloud). |
| **Operating Systems and Versions Used** | 🔴 Not specified (However, the system interacts with multiple platforms, including Android, iOS, Windows, macOS, and Linux). |
| **Programming Languages and Versions Used** | 🟢 Python, Dart, Flutter (Python is mentioned for cloud functions, and Dart is used for developing the Flutter mobile application). |
| **Web Frameworks and Versions Used** | 🔴 Not specified. |

---

## **Description of the Application/System Being Threat Modeled**

The system is a **Cyber-Physical System (CPS)** designed to **optimize and monitor window cleaning operations**. This system integrates **Internet of Things (IoT) devices with cloud-based services** to provide **real-time data exchange and operational efficiency**.

### **Key Components:**

- **IoT Hardware:** The system utilizes **Arduino microcontrollers equipped with various sensors**, including **Hall Effect sensors for monitoring water flow, temperature sensors, GPS for location tracking, and Bluetooth Low Energy (BLE) for communication with mobile devices**.
- **Mobile Application:** Developed using **Flutter**, the **mobile application allows operators to monitor and control the IoT hardware remotely**. It connects to the **IoT devices via BLE** and forwards **real-time data to cloud-based endpoints**.
- **Cloud Services:** The system uses **Google Cloud Platform (GCP) services**, particularly **Google Firestore**, a **NoSQL database**, to **store and manage real-time data**. **Firebase Authentication is employed to secure access**, ensuring that **only authorized users can create, read, update, or delete data**.
- **Data Communication:** The system supports **multiple communication protocols**, including **HTTP POST requests for sending data to API gateways**, and **BLE for local communication with the IoT hardware**.
- **External Dependencies:** The system **relies on external services** such as **Shopify for targeted advertisements** based on **data analytics**, and various **Python libraries** for **handling data communication and storage**.
- **Additional Assets:** The system includes **water purification components in the vans**, **actuators to control water flow**, and a **digital supply chain infrastructure** that **processes and commercializes data related to resource usage and route optimization**.

The **CPS is designed to enhance the efficiency and reliability of window cleaning operations** by providing **real-time data on resource usage, route optimization, and equipment status**. This includes **managing physical processes such as water purification**, which is **critical for the window cleaning process**.

---

## **Justification for Case Study 15: Cyber-Physical Systems - Window Cleaning Business**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System Description or DFD** | 🟢 **5** | The paper includes a **clear and detailed DFD** illustrating **the architecture and data flows** within the **Cyber-Physical System (CPS)** used for **window cleaning operations**. |
| **Application Type** | 🟢 **5** | The system is **explicitly described as a Cyber-Physical System (CPS)**, integrating **IoT devices and cloud services** to **optimize and monitor window cleaning operations**. |
| **Industry Sector** | 🟢 **5** | The **industry sector is clearly identified as Commercial Services**, specifically focusing on **window cleaning operations using advanced IoT and cloud technologies**. |
| **Data Sensitivity** | 🟢 **5** | **High data sensitivity is inferred** due to the **handling of sensitive operational data**, such as **GPS tracking, real-time IoT data, and business intelligence related to resource usage**. |
| **Internet Facing** | 🟢 **5** | The system is **explicitly described as internet-facing**, with **connectivity to external networks**, including **cloud services for data storage and management**. |
| **Compliance Requirements** | 🟡 **3** | **No compliance requirements** are mentioned in the paper, **representing a gap in regulatory adherence**. |
| **Authentication Methods** | 🟢 **5** | The paper mentions **Firebase Authentication and API Key** for **securing access to the Firestore database and mobile applications**. |
| **Technical Details** | 🟡 **2** | The paper mentions **Google Firestore and Python**, but **lacks comprehensive details on operating systems and programming languages**, leaving **some gaps in technical depth**. |
| **Threat Details** | 🟢 **5** | The **threats are comprehensively defined using the STRIDE framework**, with **clear explanations of vulnerabilities and attack vectors relevant to the CPS**. |

---

### **Total Score: 39 → 🟢 High Quality**

The total score for this case study is **39**, classifying it as **High Quality**.