/* This is a generated file, don't edit */

#define NUM_APPLETS 77
#define KNOWN_APPNAME_OFFSETS 4

const uint16_t applet_nameofs[] ALIGN2 = {
96,
202,
308,
};

const char applet_names[] ALIGN1 = ""
"ash" "\0"
"awk" "\0"
"basename" "\0"
"bash" "\0"
"bunzip2" "\0"
"bzcat" "\0"
"bzip2" "\0"
"cat" "\0"
"comm" "\0"
"cp" "\0"
"cut" "\0"
"date" "\0"
"dd" "\0"
"df" "\0"
"diff" "\0"
"dirname" "\0"
"dmesg" "\0"
"du" "\0"
"echo" "\0"
"egrep" "\0"
"env" "\0"
"expr" "\0"
"false" "\0"
"fgrep" "\0"
"find" "\0"
"grep" "\0"
"groups" "\0"
"gunzip" "\0"
"gzip" "\0"
"head" "\0"
"hostname" "\0"
"id" "\0"
"ifconfig" "\0"
"kill" "\0"
"killall" "\0"
"less" "\0"
"ln" "\0"
"ls" "\0"
"mkdir" "\0"
"mktemp" "\0"
"mv" "\0"
"paste" "\0"
"patch" "\0"
"ping" "\0"
"printenv" "\0"
"printf" "\0"
"ps" "\0"
"readlink" "\0"
"realpath" "\0"
"rm" "\0"
"rmdir" "\0"
"sed" "\0"
"seq" "\0"
"sh" "\0"
"sleep" "\0"
"sort" "\0"
"stat" "\0"
"sync" "\0"
"sysctl" "\0"
"tail" "\0"
"tar" "\0"
"tee" "\0"
"test" "\0"
"touch" "\0"
"tr" "\0"
"true" "\0"
"uname" "\0"
"uniq" "\0"
"unxz" "\0"
"vi" "\0"
"wc" "\0"
"wget" "\0"
"whoami" "\0"
"xargs" "\0"
"xz" "\0"
"yes" "\0"
"zcat" "\0"
;

#define APPLET_NO_ash 0
#define APPLET_NO_awk 1
#define APPLET_NO_basename 2
#define APPLET_NO_bash 3
#define APPLET_NO_bunzip2 4
#define APPLET_NO_bzcat 5
#define APPLET_NO_bzip2 6
#define APPLET_NO_cat 7
#define APPLET_NO_comm 8
#define APPLET_NO_cp 9
#define APPLET_NO_cut 10
#define APPLET_NO_date 11
#define APPLET_NO_dd 12
#define APPLET_NO_df 13
#define APPLET_NO_diff 14
#define APPLET_NO_dirname 15
#define APPLET_NO_dmesg 16
#define APPLET_NO_du 17
#define APPLET_NO_echo 18
#define APPLET_NO_egrep 19
#define APPLET_NO_env 20
#define APPLET_NO_expr 21
#define APPLET_NO_false 22
#define APPLET_NO_fgrep 23
#define APPLET_NO_find 24
#define APPLET_NO_grep 25
#define APPLET_NO_groups 26
#define APPLET_NO_gunzip 27
#define APPLET_NO_gzip 28
#define APPLET_NO_head 29
#define APPLET_NO_hostname 30
#define APPLET_NO_id 31
#define APPLET_NO_ifconfig 32
#define APPLET_NO_kill 33
#define APPLET_NO_killall 34
#define APPLET_NO_less 35
#define APPLET_NO_ln 36
#define APPLET_NO_ls 37
#define APPLET_NO_mkdir 38
#define APPLET_NO_mktemp 39
#define APPLET_NO_mv 40
#define APPLET_NO_paste 41
#define APPLET_NO_patch 42
#define APPLET_NO_ping 43
#define APPLET_NO_printenv 44
#define APPLET_NO_printf 45
#define APPLET_NO_ps 46
#define APPLET_NO_readlink 47
#define APPLET_NO_realpath 48
#define APPLET_NO_rm 49
#define APPLET_NO_rmdir 50
#define APPLET_NO_sed 51
#define APPLET_NO_seq 52
#define APPLET_NO_sh 53
#define APPLET_NO_sleep 54
#define APPLET_NO_sort 55
#define APPLET_NO_stat 56
#define APPLET_NO_sync 57
#define APPLET_NO_sysctl 58
#define APPLET_NO_tail 59
#define APPLET_NO_tar 60
#define APPLET_NO_tee 61
#define APPLET_NO_test 62
#define APPLET_NO_touch 63
#define APPLET_NO_tr 64
#define APPLET_NO_true 65
#define APPLET_NO_uname 66
#define APPLET_NO_uniq 67
#define APPLET_NO_unxz 68
#define APPLET_NO_vi 69
#define APPLET_NO_wc 70
#define APPLET_NO_wget 71
#define APPLET_NO_whoami 72
#define APPLET_NO_xargs 73
#define APPLET_NO_xz 74
#define APPLET_NO_yes 75
#define APPLET_NO_zcat 76

#ifndef SKIP_applet_main
int (*const applet_main[])(int argc, char **argv) = {
ash_main,
awk_main,
basename_main,
ash_main,
bunzip2_main,
bunzip2_main,
bzip2_main,
cat_main,
comm_main,
cp_main,
cut_main,
date_main,
dd_main,
df_main,
diff_main,
dirname_main,
dmesg_main,
du_main,
echo_main,
grep_main,
env_main,
expr_main,
false_main,
grep_main,
find_main,
grep_main,
id_main,
gunzip_main,
gzip_main,
head_main,
hostname_main,
id_main,
ifconfig_main,
kill_main,
kill_main,
less_main,
ln_main,
ls_main,
mkdir_main,
mktemp_main,
mv_main,
paste_main,
patch_main,
ping_main,
printenv_main,
printf_main,
ps_main,
readlink_main,
realpath_main,
rm_main,
rmdir_main,
sed_main,
seq_main,
ash_main,
sleep_main,
sort_main,
stat_main,
sync_main,
sysctl_main,
tail_main,
tar_main,
tee_main,
test_main,
touch_main,
tr_main,
true_main,
uname_main,
uniq_main,
unxz_main,
vi_main,
wc_main,
wget_main,
whoami_main,
xargs_main,
unxz_main,
yes_main,
gunzip_main,
};
#endif

