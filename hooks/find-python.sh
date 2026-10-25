# Sourced by run.sh and hooks/run-hook.sh (POSIX sh). find_python sets PYTHON_BIN,
# plus PYTHON_ARGS=-3 for the py launcher, to the first interpreter that actually runs.
#
# Every PATH entry is tried, not just the first hit per name: on Windows the Microsoft
# Store python3/python App execution aliases sit early on PATH (WindowsApps is the first
# user PATH entry) and exit non-zero, hiding a real install later on PATH. Relative and
# empty entries are skipped so a python in the current repo is never executed.
find_python() {
    PYTHON_BIN=""
    PYTHON_ARGS=""
    _fp_ifs=$IFS
    IFS=:
    set -f
    for _fp_name in python3 python; do
        for _fp_dir in $PATH; do
            case $_fp_dir in /*) ;; *) continue ;; esac
            for _fp_cand in "$_fp_dir/$_fp_name" "$_fp_dir/$_fp_name.exe"; do
                if [ -e "$_fp_cand" ] && [ ! -d "$_fp_cand" ] \
                    && "$_fp_cand" -c 0 </dev/null >/dev/null 2>&1; then
                    PYTHON_BIN=$_fp_cand
                    break 3
                fi
            done
        done
    done
    set +f
    IFS=$_fp_ifs
    # Stock python.org Windows installs may register only the py launcher.
    if [ -z "$PYTHON_BIN" ] && command -v py >/dev/null 2>&1 \
        && py -3 -c 0 </dev/null >/dev/null 2>&1; then
        PYTHON_BIN=py
        PYTHON_ARGS=-3
    fi
    [ -n "$PYTHON_BIN" ]
}
