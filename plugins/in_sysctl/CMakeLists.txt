set(src
  in_sysctl.c
  in_sysctl_sysctl.c
  in_sysctl_tree.c)

FLB_PLUGIN(in_sysctl "${src}" "")
