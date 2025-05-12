# 10. Use Case: Contact Tracing Applications

**Reference:**

Hasan, R., Hoque, M. A., & Hasan, R. (2022). **Towards a Threat Model and Security Analysis for Contact Tracing Applications.** 2022 IEEE 8th World Forum on Internet of Things (WF-IoT), 1–6.

https://doi.org/10.1109/wf-iot54382.2022.10152080

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes Data Flow Diagrams (DFDs) that illustrate the architecture and data flows within centralized and decentralized contact tracing systems). |
| **Application Type** | 🟢 Mobile Application (specifically a Contact Tracing Application used for tracking potential COVID-19 exposures). |
| **Industry Sector** | 🟢 Healthcare (The focus is on contact tracing, which is directly related to public health efforts). |
| **Data Sensitivity** | 🟢 High (Inferred due to the handling of sensitive personal data such as location, health status, and contact history). |
| **Internet Facing** | 🟢 Yes (The system includes connectivity with external networks, including communication with central servers and other devices). |
| **Number of Employees** | 🔴 Unknown (Not mentioned in the document). |
| **Compliance Requirements** | 🟡 HIPAA (Inferred due to the handling of personal health information in the United States, where HIPAA governs the protection of such data). |
| **Authentication Methods** | 🟢 Not specified (The document discusses security concerns but does not specify the authentication methods used). |
| **Database Technologies & Versions** | 🔴 Not specified. |
| **Operating Systems & Versions** | 🟡 iOS and Android are inferred. |
| **Programming Languages & Versions** | 🔴 Not specified. |
| **Web Frameworks & Versions** | 🔴 Not specified. |

---

## **Description of the Application/System Being Threat Modeled**

The system under consideration is a **contact tracing application** used to **monitor and control the spread of COVID-19** by **tracking users' interactions and proximity to one another**. The **architecture of the system** is presented in **both centralized and decentralized forms**:

- **Centralized Architecture:** In this setup, **users must register with a central server**, which **generates temporary IDs** for each device. These **IDs are exchanged between devices** when they come into contact. If a **user tests positive for COVID-19**, the collected **data, including the temporary IDs, is sent to the central server**, which then **maps the contacts and notifies other users** who may have been exposed.
- **Decentralized Architecture:** In this architecture, most of the **data processing occurs on the user's device**. The **application generates rolling keys locally** on each device, which are **exchanged with other devices** during interactions. If a **user tests positive**, the **rolling keys are uploaded to the server**, where **other users can download and compare them with their stored keys to determine potential exposure**.

### **Key Components:**

- **User Devices:** **Smartphones or tablets** equipped with the **contact tracing app**. These devices utilize **Bluetooth and/or GPS** to **monitor and record close contacts** with other users.
- **User Credentials:** Data related to **user registration and login**, including **usernames, passwords, and phone numbers**, when required by the application.
- **Device Credentials:** Information about the user's device, such as **IMEI, identification keys, and IP addresses**.
- **Mobile Application:** The **client-side application** installed on **user devices**. This application **manages the collection, storage, and processing of proximity data** and provides **alerts to users regarding potential exposure**.
- **Data in Application:** The application **stores data locally**, including **encryption keys, proximity values, and Received Signal Strength Indicator (RSSI) data**.
- **Central Server (for Centralized Architecture):** The server **responsible for generating temporary IDs**, collecting **data from user devices**, **processing that data to identify potential exposures**, and **notifying users** who may have been in contact with an infected individual.
- **Data Storage:** **Data centers or cloud storage facilities** used for **storing, processing, and managing** the data collected by the application.
- **Patient Data:** Information about **users who have tested positive for COVID-19**, including potentially **sensitive data** such as **phone numbers, duration of illness, and geographical location**.
- **Service Server (for Decentralized Architecture):** Handles the **management of rolling keys** and facilitates the **comparison of keys to identify potential exposures**.
- **Log Files:** Contain **timestamps, device configurations, and other metadata** related to the **operation of the application**.

The system is **designed to operate in a networked environment**, where **data flows between user devices, central servers, and potentially other external systems**.

---

## **Justification for Case Study 10: Contact Tracing Applications**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System Description or DFD** | 🟢 **5** | The paper provides **detailed DFDs illustrating data flows** in **centralized and decentralized contact tracing architectures**, clearly explaining **how data moves between components**. |
| **Application Type** | 🟢 **5** | The application type is **explicitly identified** as a **Mobile Application** for **contact tracing**, focused on **tracking COVID-19 exposures** through **smartphones**. |
| **Industry Sector** | 🟢 **5** | The industry sector is **clearly stated** as **Healthcare**, as the **system is directly related to public health and pandemic response**. |
| **Data Sensitivity** | 🟢 **5** | **High data sensitivity inferred** due to the **handling of sensitive personal information**, such as **health status, location, and contact history**, which are **crucial in contact tracing applications**. |
| **Internet Facing** | 🟢 **5** | The system is **internet-facing**, as **described in the paper**, with **data exchanged between users' devices and central servers or decentralized networks**. |
| **Compliance Requirements** | 🟡 **3** | **HIPAA is inferred**, given the **handling of personal health data in the context of the U.S.**, but the paper **does not explicitly mention compliance with this or any other regulation**. |
| **Authentication Methods** | 🟢 **5** | The paper **does not specify any authentication methods**, leaving a **significant gap in the security discussion**. |
| **Technical Details** | 🟡 **2** | **No specific technical details** regarding **databases, operating systems, or programming languages** are provided, **limiting the understanding of the underlying infrastructure**. |
| **Threat Details** | 🟢 **5** | The **threats are comprehensively defined using the STRIDE framework**, with **clear explanations of the risks involved** in **both centralized and decentralized contact tracing systems**. |

---

### **Total Score: 35 → 🟢 High Quality**

The total score for this case study is **35**, classifying it as **High Quality**.