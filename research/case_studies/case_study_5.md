# 5. Use Case: Distributed Control system in Oil Refinery

**Reference:**

Kim, K. H., Kim, K., & Kim, H. K. (2022). **STRIDE-based threat modeling and DREAD evaluation for the distributed control system in the oil refinery.** ETRI Journal, 44(6), 991–1003.

https://doi.org/10.4218/etrij.2021-0181

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes Data Flow Diagrams (DFDs) illustrating the data flows within the distributed control system (DCS) in an oil refinery). |
| **Application Type** | 🟢 Industrial Control System (ICS) (specifically a Distributed Control System (DCS) in an oil refinery). |
| **Industry Sector** | 🟢 Oil and Gas (The focus is on DCS operations within an oil refinery). |
| **Data Sensitivity** | 🟢 High (This is inferred due to the critical nature of the data handled within the DCS, which impacts safety and operational integrity). |
| **Internet Facing** | 🟢 Yes (The DCS is connected to corporate networks and the internet, increasing its exposure to cybersecurity threats). |
| **Number of Employees** | 🔴 Unknown (Not mentioned in the document). |
| **Compliance Requirements** | 🟡 IEC 62443 (Inferred due to relevance to cybersecurity requirements for industrial automation and control systems). |
| **Authentication Methods** | 🟢 Active Directory (AD) is used for centralized user account management and authentication within the DCS environment. |
| **Database Technologies & Versions** | 🔴 Not specified. |
| **Operating Systems & Versions** | 🟡 Various general-purpose operating systems are mentioned, including those based on TCP/IP protocols. Windows and Linux are inferred. These two would cover the most likely operating systems mentioned in the context of a Distributed Control System (DCS) in an oil refinery. |
| **Programming Languages & Versions** | 🔴 Not specified. |
| **Web Frameworks & Versions** | 🔴 Not specified. |

---

## **Description of the Application/System Being Threat Modeled**

The system under threat modeling is a **Distributed Control System (DCS)** within an **oil refinery**. The **DCS is a critical component** of the refinery's **operational technology (OT)** and is responsible for **centrally collecting information from multiple sensors**, **analyzing this data**, and **sending necessary commands to actuators** to adjust the values. The system's **primary objective** is to **maintain an optimal operating environment within the refinery**.

### **Key Components:**

- **DCS Controller:** Centralizes **process control functions** and **communicates with sensors and actuators** to manage the refinery's operations.
- **DCS Servers:** Provide **screen values and user profile information** to **operator and engineering workstations (OWS and EWS)**.
- **Engineering Workstation (EWS):** Used by **engineers to manage controller settings and configurations** within the DCS.
- **Operator Workstation (OWS):** Used by **operators to monitor and adjust process set-point values**.
- **Active Directory (AD):** Provides **centralized user account management and authentication** within the DCS environment.
- **GPS Server:** Provides **time synchronization** within the **DCS network**.
- **Historian:** Stores **process and operational data for trend analysis**, which is **crucial for monitoring and improving refinery operations**.
- **Safety Instrumented System (SIS):** Although **not the primary focus** of this threat model, the **SIS works in conjunction with the DCS** to **ensure fail-safe operation against dangerous conditions**.

The system operates in an **isolated network**, interacting with **various components within a production process**. However, due to the **increased connectivity with corporate networks and the internet**, the system is **exposed to cybersecurity risks**. The DCS is **designed to prioritize the CIA triad—Confidentiality, Integrity, and Availability**, with a **particular emphasis on maintaining availability** to ensure **continuous operations in the refinery environment**.

---

## **Justification for Case Study 5: Distributed Control System in Oil Refinery**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System DFD** | 🟢 **5** | The paper includes a **comprehensive and accurate DFD**, clearly illustrating the **data flows and interactions** between the **Distributed Control System (DCS) components**. |
| **Application Type** | 🟢 **5** | The application is **explicitly identified** as an **Industrial Control System (ICS)**, specifically focusing on a **Distributed Control System (DCS)** within the context of an **oil refinery**. |
| **Industry Sector** | 🟢 **5** | The **industry sector is clearly stated** as **Oil and Gas**, directly relevant to the **system being threat-modeled** in the **refinery context**. |
| **Data Sensitivity** | 🟢 **5** | **High data sensitivity is inferred** due to the **critical nature of the operational and process data in the DCS**, impacting **both safety and operational integrity**. |
| **Internet Facing** | 🟢 **5** | The **DCS is explicitly described as being connected to corporate networks and the internet**, increasing its **exposure to cybersecurity risks**. |
| **Compliance Requirements** | 🟡 **3** | Compliance with **IEC 62443** is **inferred**, but **not explicitly mentioned**, leaving some **uncertainty about specific regulatory adherence**. |
| **Authentication Methods** | 🟢 **5** | The use of **Active Directory (AD)** for **centralized user authentication and account management** is **explicitly mentioned in the paper**. |
| **Technical Details** | 🔴 **2** | **General-purpose operating systems such as Windows and Linux are inferred**, but **specific versions and deeper technical details are not provided**. |
| **Threat Details** | 🟢 **5** | The **threats are well-defined** and **categorized using the STRIDE model**, with **clear explanations of risks and effective mitigations**, making the **analysis comprehensive**. |

---

### **Total Score: 40 → 🟢 High Quality**

The total score for this case study is **40**, classifying it as **High Quality**.