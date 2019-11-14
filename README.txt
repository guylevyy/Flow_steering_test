Test name:
    steering_test

Author:
       Guy Levi

Short description:
        Run one way traffic using IB verbs.

Dependencies:
        Verification tools (/mswg/projects/ver_tools/reg2_latest/install.sh)
        rdma-core installation
    
Supported OSes:
        Linux

Examples:
        On server: ./steering_test -d mlx5_1 -i 16
        On client: ./steering_test -d mlx5_1 --ip=10.134.203.1 -i 16

Usage notes:
        1. None.

