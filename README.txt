Test name:
    steering_test

Author:
       Guy Levi

Short description:
        Create steering resources on server and run one way Ethernet
        traffic from client.
        The steering flows can be created by verbs API either mlx5dv_dr
        API according to command line parameters

Dependencies:
        Verification tools (/mswg/projects/ver_tools/reg2_latest/install.sh)
        OFED's rdma-core installation (until upstream SW steering will support rx_nic)
    
Supported OSes:
        Linux

Examples:
        On server: sudo ./steering_test -d mlx5_1 -i 16 --mac=ec:0d:9a:d4:2d:d9
        On client: sudo ./steering_test -d mlx5_1 --ip=10.134.203.1 -i 16 --mac=ec:0d:9a:d4:2d:d8

Usage notes:
        1. Command must be run by root user to succeed to open RAW_PACKET QP and flow rules.
        2. Don't use the local mac of the EN driver's interface.
           You can use which MAC address you wish.

