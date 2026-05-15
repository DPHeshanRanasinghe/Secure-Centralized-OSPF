SC-OSPF: Secure and Centralized OSPF
=====================================

EN2150 Communication Network Engineering 


Overview
--------
This repository contains the simulation code for SC-OSPF, a novel routing
protocol designed to address two well-known limitations of standard OSPF:

1. Lack of strong LSA authentication -- standard OSPF does not verify the
   origin of Link State Advertisements, making it vulnerable to LSA injection
   attacks where a compromised router can corrupt the routing tables of all
   other routers in the domain.

2. Flooding-based convergence -- OSPF floods LSAs wave by wave across the
   network, meaning convergence time grows with the network diameter. A
   50-router network requires 7 flooding rounds and 9,800 control messages
   for a single convergence cycle.

SC-OSPF fixes both issues by:
- Requiring every LSA to be signed with HMAC-SHA256 before the controller
  will process it.
- Using a central controller that collects all LSAs directly (no flooding),
  runs Dijkstra once for all routers, and distributes forwarding tables back.
  This always converges in exactly 2 rounds regardless of network size.


Project Structure
-----------------
sc_ospf_project/
    topology.py       Network topology generation utilities.
                      Provides a fixed 10-router demo topology and a
                      Watts-Strogatz small-world random topology generator.

    ospf.py           Standard OSPF simulation.
                      Implements LSA flooding, LSDB construction, Dijkstra
                      route computation at each router, and LSA injection
                      attack simulation (no authentication).

    sc_ospf.py        SC-OSPF simulation.
                      Implements the central controller, HMAC-SHA256
                      key management and verification, two-round convergence,
                      and the same LSA injection attack (which is blocked).

    main.py           Main experiment runner.
                      Runs all experiments and generates all six figures
                      used in the report.

    fig1_topology.png           Demo network topology diagram
    fig2_convergence_rounds.png Convergence rounds vs network size
    fig3_message_overhead.png   Control message overhead comparison
    fig4_attack_comparison.png  LSA injection attack impact
    fig5_routing_integrity.png  Routing table before/after attack
    fig6_scalability.png        Scalability trend comparison


Requirements
------------
Python 3.8 or higher is required. The following packages must be installed:

    networkx >= 2.6
    matplotlib >= 3.4
    numpy >= 1.21

All three are standard packages available on PyPI.


Installation
------------
It is recommended to use a virtual environment, though not required.

To install the dependencies:

    pip install networkx matplotlib numpy

If you are on a system where pip installs globally, you may need:

    pip install --user networkx matplotlib numpy


Running the Simulation
----------------------
Navigate to the project directory and run:

    python main.py

The script will run all experiments in sequence and print results to the
terminal. All six figures will be saved as PNG files in the same directory.

Expected terminal output covers four stages:
  - Figure 1: Topology generation and node/link count
  - Basic convergence demo on the 10-router network
  - Scalability tests on networks from 5 to 50 routers
  - LSA injection attack simulation on both protocols

Expected runtime is under 30 seconds on any modern machine.


Reproducing Specific Results
-----------------------------
All random topologies are generated with a fixed seed (seed=42), so results
are fully reproducible without any changes to the code.

To change the network size range for scalability testing, edit the `sizes`
list in the `run_convergence_experiment()` and `run_message_experiment()`
functions in main.py.

To change the attack scenario (attacker router, victim router, or fake cost),
edit the `ATTACKER` and `VICTIM` constants near the bottom of main.py.


How the HMAC Authentication Works
----------------------------------
Each router has a pre-shared 256-bit secret key known only to that router
and the controller. When a router sends an LSA, it computes:

    signature = HMAC-SHA256(K_router, JSON_sorted(payload))

The controller verifies this by recomputing the expected signature using
the key it holds for that router. If the signatures match, the LSA is
accepted. If not, it is silently dropped.

An attacker impersonating another router does not have the victim's key,
so the signature they produce will never match what the controller expects.
This is why the attack has zero effect on SC-OSPF while corrupting 100% of
routers in standard OSPF.

Constant-time comparison (hmac.compare_digest) is used to prevent timing
side-channel attacks.


Simulation Assumptions
-----------------------
The simulation models message exchange in discrete rounds rather than
real time. One round represents one complete wave of message exchange
across the network. This is a standard approach for comparing protocol
convergence behavior in network simulation research.

The HMAC keys are derived deterministically in the prototype for
simplicity. A production implementation would use a proper PKI system
for key distribution and rotation.

The fallback mechanism (routers reverting to standard OSPF if the
controller is unreachable) is described in the report but not simulated
in this prototype, as it is identical to standard OSPF flooding behavior.


Output Files
------------
After running main.py, the following files will be present in the directory:

    fig1_topology.png
        The 10-router demo network used for attack demonstration.

    fig2_convergence_rounds.png
        OSPF vs SC-OSPF convergence rounds for network sizes 5 to 50.
        Shows SC-OSPF is flat at 2 rounds while OSPF grows.

    fig3_message_overhead.png
        Total control messages per convergence cycle.
        At 50 routers: OSPF generates 9,800 messages vs SC-OSPF's 100.

    fig4_attack_comparison.png
        Side-by-side comparison of LSA injection attack impact.
        OSPF: 9/9 routers corrupted. SC-OSPF: 0/9 routers affected.

    fig5_routing_integrity.png
        Router 0 forwarding table before and after the attack for both
        protocols. OSPF table shows corrupted entries; SC-OSPF is unchanged.

    fig6_scalability.png
        Trend plot showing OSPF convergence growing with diameter while
        SC-OSPF stays constant.


Known Limitations
-----------------
- The simulation does not model actual packet transmission time, queuing
  delay, or link bandwidth. It measures convergence in logical rounds only.
- The prototype does not implement the hot-standby redundant controller
  described in the report. That remains as future work.
- HMAC key provisioning is simplified for the prototype. Real deployment
  would require a secure key distribution mechanism.


References
----------
RFC 1058  -- Routing Information Protocol (RIP v1)
RFC 2453  -- RIP Version 2
RFC 2328  -- OSPF Version 2
RFC 5340  -- OSPF for IPv6
RFC 1142  -- OSI IS-IS Intra-domain Routing Protocol
RFC 1195  -- Use of IS-IS for Routing in TCP/IP Environments
RFC 4271  -- Border Gateway Protocol 4 (BGP-4)

Hagberg et al., "Exploring network structure, dynamics, and function
using NetworkX," Proc. 7th Python in Science Conf. (SciPy), 2008.