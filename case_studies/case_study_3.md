# 3. Use Case: 5G Core Slicing

**Reference:**

Sattar, D., Vasoukolaei, A. H., Crysdale, P., & Matrawy, A. (2021). **A STRIDE Threat Model for 5G Core Slicing.** 2021 IEEE 4th 5G World Forum (5GWF), 247–252.

https://doi.org/10.1109/5gwf52925.2021.00050

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes diagrams that illustrate trust boundaries and component interactions, which are part of the system architecture.) |
| **Application Type** | 🟢 5G/Wireless System (The application involves 5G core slicing, which is a key feature of 5G wireless networks.) |
| **Industry Sector** | 🟢 Telecommunications (The system is directly related to telecommunications infrastructure.) |
| **Data Sensitivity** | 🟢 High (This is inferred from the handling of critical and potentially sensitive data within the 5G network slices.) |
| **Internet Facing** | 🟢 Yes (5G core slicing involves interactions with external networks, making it internet-facing.) |
| **Number of Employees** | 🔴 Unknown (The document does not provide details on the number of employees involved.) |
| **Compliance Requirements** | 🟢 3GPP TS 33.501 (This standard is relevant to 5G security architecture and is part of the system's compliance requirements.) |
| **Authentication Methods** | 🔴 None (There is no explicit mention of authentication methods being implemented in the system prior to threat modeling recommendations.) |
| **Database Technologies & Versions** | 🔴 Not specified (The document does not detail any specific database technologies or versions.) |
| **Operating Systems & Versions** | 🔴 Not specified (The document does not detail the operating systems in use.) |
| **Programming Languages & Versions** | 🔴 Not specified (The document does not detail the programming languages used.) |
| **Web Frameworks & Versions** | 🔴 Not specified (The document does not detail the web frameworks in use.) |

---

## **Description of the Application/System Being Threat Modeled**

The system being threat-modeled is a **5G core slicing implementation** within a telecommunications network. This system enables network operators to create **isolated, virtualized segments (or slices) of the 5G network**, each tailored to specific use cases, such as **enhanced mobile broadband, massive machine-type communications, and ultra-reliable, low-latency communications**.

### **Key Components:**

- **Network Slices:** Independent virtual segments within the 5G network, each optimized for different performance and functional requirements. These slices operate in isolation, ensuring that each slice meets the specific needs of its use case without impacting others.
- **Network Functions (NFs):** Virtualized components that perform specific tasks within the 5G core network, including both **user plane and control plane functions**. These functions are integral to the operation of each network slice.
- **Virtual Network Functions (VNFs):** These are **virtualized instances of network functions** that operate on hypervisors or within containers, forming the backbone of each network slice. VNFs are dynamically managed and allocated based on the needs of the network slices.
- **Trust Boundaries:** The system includes **multiple trust boundaries**, which are critical for maintaining security and privacy in a **multi-tenant environment**. These boundaries distinguish between trusted and untrusted zones within the network infrastructure, particularly where data crosses from one administrative domain to another.
- **Orchestration and Management:** Managed by the **Network Functions Virtualization Orchestrator (NFVO)** and related entities, these components **control the lifecycle, deployment, and resource allocation of network slices**. The NFVO ensures that each slice is instantiated, configured, and managed according to its specific requirements.
- **Edge and Cloud Computing:** The system incorporates **both edge and cloud computing nodes** to optimize **resource allocation and processing capabilities**. This allows for **efficient management of latency-sensitive applications** and **scalable network resources**.
- **External Interfaces:** These include **connections to external networks, partners, and service providers**, enabling the 5G network to extend its capabilities and services beyond the traditional infrastructure. These interfaces are essential for the **dynamic and flexible nature of 5G slicing**.

The **5G core slicing system** operates in a highly **virtualized and dynamic environment**, allowing for **flexible resource allocation across multiple domains and service providers**. The architecture is designed to support **various 5G use cases**, ensuring **high levels of performance, security, and scalability**.

---

## **Justification for Case Study 3: 5G Core Slicing**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System DFD** | 🟢 **5** | The paper includes **clear and detailed DFDs** illustrating **trust boundaries and component interactions** within the 5G core slicing system, enhancing understanding of the system's operation. |
| **Application Type** | 🟢 **5** | The application is explicitly identified as a **5G/Wireless System**, focusing on **network slicing**, a core feature of 5G infrastructure. |
| **Industry Sector** | 🟢 **5** | The paper clearly states that the system is within the **Telecommunications** industry, focusing on **5G network operations**. |
| **Data Sensitivity** | 🟢 **5** | **High data sensitivity inferred** due to the **critical and sensitive nature of the data** flowing within the network slices, including **user plane and control plane data**. |
| **Internet Facing** | 🟢 **5** | The system is **internet-facing**, involving interactions with **external networks and cloud services**, making this clear in the system's architecture. |
| **Compliance Requirements** | 🟢 **5** | Compliance with **3GPP TS 33.501** is explicitly mentioned, which governs the **security architecture for 5G systems**. |
| **Authentication Methods** | 🔴 **1** | **Authentication methods are not mentioned**, despite the **security focus of the paper**, representing a significant gap in the design discussion. |
| **Technical Details** | 🔴 **1** | No technical details regarding **databases, operating systems, or programming languages** are provided in the paper, limiting the technical understanding. |
| **Threat Details** | 🟢 **5** | The threats are **well-organized using the STRIDE model**, with **clear and comprehensive explanations of risks and suggested mitigations**. |

---

### **Total Score: 37 → 🟢 High Quality**

The total score for this case study is **37**, classifying it as **High Quality**.