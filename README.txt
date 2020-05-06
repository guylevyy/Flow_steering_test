Test name:
    steering_test

Author:
       Guy Levi

Short description:
        This test purpose is verifying the steering driver functionality
        for mlx5dv_dr API.
        This test has several case as follow:
        Case 0: Create steering resources on server and run one way Ethernet
        traffic from client.
        Case 1: Create big scale of steering resources over the client
        (tables, matchers and rules).
        Case 2: Create steering resources over the client with duplicate rules.

Dependencies:
        Verification tools (/mswg/projects/ver_tools/reg2_latest/install.sh)
        OFED's rdma-core installation (until upstream SW steering will support rx_nic)
    
Supported OSes:
        Linux

Examples 1:
        On server: sudo ./steering_test -d mlx5_1 -t 0 -i 16 --mac=00:00:00:ff:ff:ff
        On client: sudo ./steering_test -d mlx5_1 -t 0 --ip=10.134.203.1 -i 16 --mac=ec:0d:9a:d4:2d:d8

Examples 2:
        On client: sudo ./steering_test -d mlx5_1 -t 1 -i 1024 --mac=ff:ff:ff:ff:ff:ff

Usage notes:
        1. Command must be run by root user to succeed to open RAW_PACKET QP and flow rules.
        2. You can use any MAC address you wish in traffic test but don't use the local
           MAC of the EN driver's interface otherwise you may loose the
           received packets.
        3. Avoid a loopback traffic in traffic test due to unkown behavior
           

