Test name:
    steering_test

Author:
       Guy Levi

Short description:
        Run one way Ethernet traffic using IB verbs.

Dependencies:
        Verification tools (/mswg/projects/ver_tools/reg2_latest/install.sh)
        rdma-core installation
    
Supported OSes:
        Linux

Examples:
        On server: sudo ./steering_test -d mlx5_1 -i 16 --mac=ec:0d:9a:d4:2d:d9
        On client: sudo ./steering_test -d mlx5_1 --ip=10.134.203.1 -i 16 --mac=ec:0d:9a:d4:2d:d8

Usage notes:
        1. Command must be run by root user to succeed to open RAW_PACKET QP and flow rules.
        2. Don't use the local mac of the EN driver's interface.
           You can use which MAC address you wish.

