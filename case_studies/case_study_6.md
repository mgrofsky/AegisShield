# 6. Use Case: Security Analysis on Social Media Networks

**Reference:**

Sharma, K. R., Chiu, W.-Y., & Meng, W. (2023). **Security Analysis on Social Media Networks via STRIDE Model (arXiv:2303.13075).** arXiv.

https://doi.org/10.48550/arXiv.2303.13075

---

## **Key Attributes**

| **Attribute** | **Value** |
| --- | --- |
| **Dataflow Diagram** | 🟢 Yes (The document includes Data Flow Diagrams (DFDs) illustrating the flow of data in social media networks like Facebook, Twitter, and LinkedIn). |
| **Application Type** | 🟢 Web Application (since "Social Media Network" is not an option, "Web Application" is the closest match). |
| **Industry Sector** | 🟡 Information Technology (This is the most relevant choice given the nature of the platforms). |
| **Data Sensitivity** | 🟡 High (Inferred due to the handling of sensitive user data, including personal information and communication details). |
| **Internet Facing** | 🟢 Yes (Social media platforms are inherently internet-facing, providing access to users globally). |
| **Number of Employees** | 🔴 Unknown (Not mentioned in the document). |
| **Compliance Requirements** | 🟡 COPPA, CCPA (Inferred as they are most likely exposed to children and operate to consumers in the state of California). |
| **Authentication Methods** | 🔴 None specified (The document discusses security vulnerabilities and threats but does not specify existing authentication methods). |
| **Database Technologies & Versions** | 🔴 Not specified. |
| **Operating Systems & Versions** | 🔴 Not specified. |
| **Programming Languages & Versions** | 🔴 Not specified. |
| **Web Frameworks & Versions** | 🔴 Not specified. |

---

## **Description of the Application/System Being Threat Modeled**

The system under threat modeling involves **social media networks**, specifically **Facebook, Twitter, and LinkedIn**. These platforms allow users to **create profiles, connect with others, share content, and communicate across a global network**. The architecture typically includes:

- **User Profiles:** Users create and manage their **profiles**, which contain **personal information, activity logs, and privacy settings**.
- **Content Sharing and Messaging:** Users can **post updates, share photos, videos, and other content, and engage in direct messaging** with other users. This content is **managed by the platform's backend systems**.
- **Backend Servers:** These servers handle the **processing of user data, content management, and real-time communication** across the platform. They manage **data storage, retrieval, and processing**, ensuring the **continuous operation of the social media network**.
- **Third-Party Integrations:** Users can **link their accounts to third-party applications**, which may introduce **additional security risks**. These integrations often require **data sharing between the social media platform and external services**.
- **Security and Privacy Controls:** The platforms provide **tools for users to manage their privacy settings, control who can see their content, and secure their accounts**. However, **the effectiveness of these controls can vary**.

This system represents a **typical setup of social media networks** where **data flows between user devices, backend servers, and third-party integrations**. These platforms are **internet-facing** and handle a **significant amount of sensitive user data**, including **personal information and communication details**, making **security a critical concern**.

---

## **Justification for Case Study 6: Security Analysis on Social Media Networks**

### **Evaluation Criteria & Scores**

| **Criteria** | **Score** | **Justification** |
| --- | --- | --- |
| **Application/System Description or DFD** | 🟢 **5** | The paper includes **detailed DFDs illustrating data flows** within **social media platforms like Facebook, Twitter, and LinkedIn**, clearly enhancing **understanding of the system's operation**. |
| **Application Type** | 🟢 **5** | The paper **explicitly identifies the system as a Web Application**, focusing on **social media platforms like Facebook, Twitter, and LinkedIn**, which **aligns with the nature of the system**. |
| **Industry Sector** | 🟡 **3** | The industry sector is **inferred as Information Technology**, given the **focus on online platforms**, though **not explicitly mentioned**. |
| **Data Sensitivity** | 🟡 **5** | **High data sensitivity inferred** due to the **handling of personal information, contact details, and communication data** across social media platforms, making it **highly sensitive**. |
| **Internet Facing** | 🟢 **5** | The system is **inherently internet-facing**, with all **social media platforms being globally accessible via web and mobile applications**, clearly indicated in the paper. |
| **Compliance Requirements** | 🔴 **1** | No specific **compliance requirements** are mentioned in the paper, such as **COPPA or CCPA**, leaving a **gap in regulatory considerations**. |
| **Authentication Methods** | 🔴 **1** | **Authentication methods are not explicitly mentioned**, despite discussions of **security threats**, which represents a **critical omission**. |
| **Technical Details** | 🔴 **1** | **No technical details** on **databases, operating systems, or programming languages** are provided, limiting the **understanding of the system’s underlying infrastructure**. |
| **Threat Details** | 🟢 **5** | The **threats are well-defined and categorized using the STRIDE framework**, with **clear descriptions of vulnerabilities** across social media platforms, making the **threat analysis comprehensive**. |

---

### **Total Score: 31 → 🟡 Moderate Quality**

The total score for this case study is **31**, classifying it as **Moderate Quality**.