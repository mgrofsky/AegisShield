# 13. Use Case: E2EE Messaging Applications

**Reference:**

Chowdhury, P. D., Sameen, M., Blessing, J., Boucher, N., Gardiner, J., Burrows, T., Anderson, R., & Rashid, A. (2023). **Threat Models over Space and Time: A Case Study of E2EE Messaging Applications (arXiv:2301.05653).** arXiv.

https://doi.org/10.48550/arXiv.2301.05653

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes Data Flow Diagrams (DFDs) that illustrate the architecture and data flows within the messaging applications analyzed). |
| **Application Type** | 🟢 Messaging Application. |
| **Industry Sector** | 🟡 Communications (focusing on secure communications and privacy within the messaging application sector). |
| **Data Sensitivity** | 🟡 High (Inferred due to the handling of sensitive personal communication data and the emphasis on privacy and security). |
| **Internet Facing** | 🟢 Yes (The messaging applications are designed to operate over the internet, making them inherently internet-facing). |
| **Number of Employees** | 🔴 Unknown (Not mentioned in the document). |
| **Compliance Requirements** | 🟡 CCPA, COPPA (Inferred based on the handling of personal data within the context of privacy-focused messaging applications, particularly for users in California and Children). |
| **Authentication Methods** | 🟢 Public/Private Key Pairs (The document details the use of long-term identity keys and ephemeral asymmetric key pairs for authentication in the messaging applications). |
| **Database Technologies & Versions** | 🟡 SQLite (Mentioned in the context of storing authentication credentials and message data, specifically for Signal). |
| **Operating Systems & Versions** | 🟡 macOS (The desktop clients were tested on MacBook Pro laptops, specifically mentioned as using macOS in the experimental setup). |
| **Programming Languages and Versions Used** | 🔴 Not specified directly (However, it is common for these types of applications to use languages like C++, Java, and Swift for development, inferred based on standard practices). |
| **Web Frameworks and Versions Used** | 🔴 Not specified. |

---

## **Description of the Application/System Being Threat Modeled**

The system comprises several **widely used end-to-end encrypted (E2EE) messaging applications**, including **Signal, WhatsApp, Viber, Wickr Me, Element, and Telegram**. These applications provide **secure communication by encrypting messages from the sender to the recipient**, ensuring that **no third party, including the service provider, can access the content**.

### **Key Components and Features:**

- **Primary Device (Mobile Application):** The main platform where **users initially set up their accounts, generate identity keys, and manage their messaging activities**. This device is **crucial for establishing the root of trust for secure communications**.
- **Companion Devices (Desktop Clients):** Linked to the **primary device**, these **desktop clients allow users to access their messaging accounts from multiple devices**. Each desktop client **generates its own identity key, authenticated by the primary device**, and can operate independently once linked.
- **Encryption Protocols:** The applications use a variety of **cryptographic protocols**, including the **Signal Protocol** for most apps, which employs **double ratcheting for forward and backward secrecy**, and other **custom protocols for apps like Telegram**.
- **Data Storage and Management:** **SQLite databases** are used by some applications, such as **Signal**, to **store authentication credentials, received messages, and pre-keys**. These databases are **typically encrypted** but may be **vulnerable to certain types of attacks if not adequately protected**.
- **Security Assumptions and Trust Boundaries:** The system **assumes that users can protect the private components of their identity keys**, with **the desktop clients extending the trust boundaries to include these additional devices**. The document **highlights the challenges posed by adversarial access to these devices**, which can **lead to security breaches if the threat models are not adequately evolved**.

---

## **Justification for Case Study 13: E2EE Messaging Applications**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System Description or DFD** | 🟢 **5** | The paper includes **detailed DFDs** that **illustrate the architecture and data flows** within **end-to-end encrypted (E2EE) messaging applications** like **Signal, WhatsApp, and Telegram**, clearly explaining **the system’s components and interactions**. |
| **Application Type** | 🟢 **5** | The application type is **explicitly identified as Messaging Applications**, focusing on **secure, encrypted communications**, clearly meeting **the rubric's criteria**. |
| **Industry Sector** | 🟡 **5** | The **industry sector is clearly inferred as Communications**, focusing on **secure communication and privacy within the messaging application sector**. |
| **Data Sensitivity** | 🟡 **5** | **High data sensitivity is explicitly discussed** due to the **handling of personal communication data**, including **private messages and contact information**, which are **core to the functionality of E2EE messaging systems**. |
| **Internet Facing** | 🟢 **5** | The **messaging applications are explicitly described as internet-facing**, as they **operate across the web and mobile devices**, facilitating **communication between users globally**. |
| **Compliance Requirements** | 🟡 **3** | **Compliance with CCPA and COPPA is inferred**, based on **the privacy focus of the applications**, but **the paper does not explicitly mention compliance with these regulations**. |
| **Authentication Methods** | 🟢 **5** | The paper **details the use of public/private key pairs for authentication**, including **long-term identity keys and ephemeral asymmetric keys**, which are **core to the security of these applications**. |
| **Technical Details** | 🟡 **3** | While **SQLite and macOS are mentioned** for **storage and system testing**, **specific details on other databases, operating systems, and programming languages** are **inferred but not comprehensively detailed**. |
| **Threat Details** | 🟢 **5** | The **threats are comprehensively defined using the STRIDE framework**, with **clear explanations of the security risks for each application**, making **the threat analysis robust**. |

---

### **Total Score: 41 → 🟢 Exceptional Quality**

The total score for this case study is **41**, classifying it as **Exceptional Quality**.