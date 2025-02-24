# SDN Project with Mininet and OpenFlow

This repository contains the implementation of a series of exercises for a **Software-Defined Networking (SDN) course project**. The project explores various networking concepts using **Mininet and the Ryu Controller**, focusing on topics such as **ARP spoofing, static routing, VLAN configuration, and multi-router communication** using **OpenFlow v1.0**.

## Table of Contents

1. [Introduction](#introduction)
2. [Project Structure](#project-structure)
   1. [Exercise 1: ARP Spoofing](#exercise-1-arp-spoofing)
   2. [Exercise 2: Static Routing](#exercise-2-static-routing)
   3. [Exercise 3: Static Routing with Two Routers](#exercise-3-static-routing-with-two-routers)
   4. [Exercise 4: VLAN with OpenFlow](#exercise-4-vlan-with-openflow)
3. [Setup and Installation](#setup-and-installation)
4. [Running the Exercises](#running-the-exercises)
5. [Expected Outcomes](#expected-outcomes)

## Introduction

This project utilizes the **Ryu SDN framework** to implement network functionalities within a **Mininet** simulated environment. The exercises provide hands-on experience in **packet manipulation, routing, VLAN management, and security threats in SDN**. By using OpenFlow, we can control network behavior dynamically, making it an excellent platform for learning and experimenting with networking protocols.

## Project Structure

### Exercise 1: ARP Spoofing

- **Script:** `arp-spoofing.py`
- **Objective:** To create an OpenFlow switch that intercepts ARP requests and sends manipulated ARP responses, effectively spoofing the ARP reply.
- **Description:**
  - The script implements an **SDN-based ARP spoofer** using Ryu. It listens for ARP requests and injects falsified ARP replies, redirecting traffic for targeted hosts. This exercise demonstrates network security vulnerabilities and how attackers manipulate network behavior in traditional and SDN-based environments.

### Exercise 2: Static Routing

- **Mininet Script:** `mininet-router.py`
- **Controller Script:** `ryu-router-frame.py`
- **Objective:** To create a static router that interconnects two switches, enabling routing between two LANs.
- **Description:**
  - This exercise introduces **basic static routing** within an SDN environment. The router inspects incoming packets, determines their next hop, and forwards them accordingly by modifying **Ethernet and IP headers**. The controller ensures ARP resolution and correct forwarding paths for inter-subnet communication.

### Exercise 3: Static Routing with Two Routers

- **Mininet Script:** `mininet-router-two.py`
- **Controller Script:** `ryu-router-two-frame.py`
- **Objective:** To implement a more complex network topology with two static routers interconnecting two LANs.
- **Description:**
  - This exercise extends the **static routing scenario by adding a second router**. Each router manages ARP and packet forwarding independently while cooperating to provide full connectivity across LANs. The challenge here is to configure and verify **correct inter-router communication and traffic forwarding**.

### Exercise 4: VLAN with OpenFlow

- **Mininet Script:** `mininet-router-vlan.py`, `mininet-router-vlan-extended.py`
- **Controller Script:** `vlan.py`
- **Objective:** To implement **VLAN segmentation** across two interconnected switches and routers using OpenFlow.
- **Description:**
  - VLANs are set up using **OpenFlow rules** to separate traffic logically within the same physical infrastructure. The controller applies **VLAN tagging and trunking mechanisms**, enabling secure traffic isolation while permitting inter-VLAN communication through an SDN router.
  - An extended scenario introduces **traffic prioritization**, where high-priority packets are assigned specific VLAN tags, enhancing network performance and security.

## Setup and Installation

### Prerequisites

- **Mininet:** Version 2.3.0 or higher
- **Ryu Controller:** Version 4.34 or higher
- **Python:** Version 3.6 or higher
- **Linux Environment:** Required for running Mininet and Ryu

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/vasilisanagno/SDN-Project-with-Mininet-and-OpenFlow.git
   cd SDN-Project-with-Mininet-and-OpenFlow
   ```

## Running the Exercises

### Exercise 1

1. **Create the topology:**
   ```bash
   sudo mn --controller remote --mac
   ```
2. **Run Ryu controller:**
   ```bash
   sudo python3 arp-spoofing.py
   ```

### Exercise 2

1. **Create the topology:**
   ```bash
   chmod +x mininet-router.py
   sudo ./mininet-router.py
   ```
2. **Run Ryu controller:**
   ```bash
   sudo python3 ryu-router-frame.py
   ```

### Exercise 3

1. **Create the topology:**
   ```bash
   chmod +x mininet-router-two.py
   sudo ./mininet-router-two.py
   ```
2. **Run Ryu controller:**
   ```bash
   sudo python3 ryu-router-two-frame.py
   ```

### Exercise 4

1. **Create the topology:**
   
   **Option 1: Standard VLAN Topology**
   ```bash
   chmod +x mininet-router-vlan.py
   sudo ./mininet-router-vlan.py
   ```
   
   **Option 2: Extended VLAN Topology**
   ```bash
   chmod +x mininet-router-vlan-extended.py
   sudo ./mininet-router-vlan-extended.py
   ```

2. **Run Ryu controller:**
   ```bash
   sudo python3 vlan.py
   ```
