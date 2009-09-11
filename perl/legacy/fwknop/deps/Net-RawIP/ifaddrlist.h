struct ifaddrlist
{
    u_int32_t addr;
    int len;
    char *device;
};


int
ifaddrlist(
    struct ifaddrlist **,
    char *
    );


