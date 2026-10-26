# Sourced by run.sh and by every bash-form hook command (POSIX sh). find_python sets
# PYTHON_BIN, plus PYTHON_ARGS=-3 for the py launcher, to the first usable interpreter.
#
# Every PATH entry is tried, not just the first hit per name: on Windows the Microsoft
# Store python3/python App execution aliases sit in WindowsApps, the first user PATH
# entry, and exit non-zero, hiding a real install later on PATH. Relative and empty
# entries are skipped so a python in the current repo is never executed.
#
# Probing costs a Python start, which a hook pays on every tool call, so by default
# only WindowsApps candidates are probed (the stubs live there; so do real Store
# installs). `find_python all` probes every candidate, for run.sh's one-off rebuild.
find_python() {
    PYTHON_BIN=""
    PYTHON_ARGS=""
    _fp_all=${1:-}
    _fp_ifs=$IFS
    IFS=:
    set -f
    for _fp_name in python3 python; do
        for _fp_dir in $PATH; do
            case $_fp_dir in /*) ;; *) continue ;; esac
            _fp_probe=$_fp_all
            case $_fp_dir in
                */[Ww][Ii][Nn][Dd][Oo][Ww][Ss][Aa][Pp][Pp][Ss] | */[Ww][Ii][Nn][Dd][Oo][Ww][Ss][Aa][Pp][Pp][Ss]/*) _fp_probe=1 ;;
            esac
            for _fp_cand in "$_fp_dir/$_fp_name" "$_fp_dir/$_fp_name.exe"; do
                [ -e "$_fp_cand" ] && [ ! -d "$_fp_cand" ] || continue
                if [ -z "$_fp_probe" ] || "$_fp_cand" -c 0 </dev/null >/dev/null 2>&1; then
                    PYTHON_BIN=$_fp_cand
                    break 3
                fi
            done
        done
    done
    set +f
    IFS=$_fp_ifs
    # Stock python.org Windows installs may register only the py launcher.
    if [ -z "$PYTHON_BIN" ] && command -v py >/dev/null 2>&1; then
        if [ -z "$_fp_all" ] || py -3 -c 0 </dev/null >/dev/null 2>&1; then
            PYTHON_BIN=py
            PYTHON_ARGS=-3
        fi
    fi
    [ -n "$PYTHON_BIN" ]
}

# Hook entry point. The manifests source this file in the hook's own shell and call
# run_hook, because the shell Claude Code starts may not have sh or dirname on PATH
# (Git for Windows' usr/bin/bash.exe run without a login profile).
run_hook() {
    if ! find_python; then
        echo "armis-appsec: no working python3/python/py on PATH; hook not run, commit gate is OFF." >&2
        return 1
    fi
    exec "$PYTHON_BIN" $PYTHON_ARGS "$@"
}
