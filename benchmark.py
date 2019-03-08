from multiprocessing import Pool
import os
import sys
import argparse
import signal
import subprocess
import time
import string
from statistics import stdev, median
from functools import partial

# launches a timed run of afl
# out_dir should be last because of how we use partial
def run_afl(afl_cmd, to, cmd_wait,out_dir):
    
    #here we are adding the output directory
    afl_args = afl_cmd.split()
    afl_args.insert(1, "-o")
    afl_args.insert(2, out_dir)
    
    # here we wrap around with a timeout command
    command = ["exec", "/usr/bin/timeout", str(to)]
    command.extend(afl_args)

    #command = [afl_bin, "-i", inp_dir, "-o", out_dir, prog_bin]
    print("Command: ", " ".join(command), "\n")
    if cmd_wait:   
        subproc = subprocess.Popen(" ".join(command), shell=True)
    else:
        subproc = subprocess.Popen(" ".join(command), shell=True, 
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
    
    # I couldn't find a way to kill the launched shell
    # it is not enough to do a sig kill, since the process will launch execute
    # the command in a separate thread/process which will not be affected by kill
    
    if cmd_wait:
        subproc.wait()

# launches experiments, waits for them to terminate, and returns their output dirs 
def run_experiments(args, do_wait, out_dirs):
    pool = Pool()
    afl_call = partial(run_afl, args.command, args.timeout, do_wait)
    pool.map(afl_call, out_dirs)
    pool.close()
    pool.join()

# extracts statistics from AFL's output folder
def parse_stats(out_dir):
    stats_file = os.path.join(out_dir, "fuzzer_stats")
    stats = dict()
    for line in open(stats_file):
        sp = line.strip().split(':')
        if len(sp) >= 2:
            stats[sp[0].strip()]=sp[1].strip().replace("%","")
    return stats

# prints statistics information
def print_stats(all_stats, sel_stats, col_stats, out=sys.stdout):
    i = 1
    for stats in all_stats:
        print("Experiment "+ str(i), file=out)
        for sel_stat in sel_stats:
            if sel_stat in stats:
                print(sel_stat, "=",stats[sel_stat], ",", file=out)
        print("", file=out)
        i+=1

    if len(all_stats) > 1:
        print("Averages\n", file=out)
        for col_stat in col_stats:
            collect = [float(stat[col_stat]) for stat in all_stats]
            print(col_stat, "[mean= ", median(collect), ",stdev=", stdev(collect), "]", file=out )

def pexit(msg):
    print(msg)
    exit(0)


def is_execute(modestr):
    return "e" in modestr

def is_collect(modestr):
    return "c" in modestr

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Utility for executing multiple AFL instances and/or collecting results')
    parser.add_argument('-m', "--mode", type=str, default="ec", choices=["ec","c","e"], help="mode of operation")
    parser.add_argument('-c', "--command", type=str, help="command to launch AFL on the binary minus the output directory")
    parser.add_argument('-o', "--output", type=str, help="experiment output dir", required=True)
    parser.add_argument('-t', "--timeout", type=int, default=10, help="timeout for each experiment")
    parser.add_argument('-n', "--numexp", type=int, default=2, help="number of experiments")
    args = parser.parse_args()
    
    do_collect = is_collect(args.mode)
    do_execute = is_execute(args.mode)

    print(args.mode, args.command, args.command is None)
    if do_execute:
        if args.command is None:
            pexit("The AFL command is required in execution mode")

    # running experiments in parallel
    if os.path.exists(args.output) is False:
        if do_collect and not do_execute:
            pexit("The output folder should exist in collection only mode")
        else:
            os.makedirs(args.output)

    out_dirs = [os.path.join(args.output, "output_"+str(i)) for i in range(1,args.numexp+1)]
    
    if do_execute:
        do_wait = do_collect
        run_experiments(args, do_wait, out_dirs)

    if do_collect:
        # fetching and collating results
        all_stats = [parse_stats(out_dir) for out_dir in out_dirs if os.path.exists(out_dir)]
        with open(os.path.join(args.output, "all_stats"), "w") as sfile:
            print_stats(all_stats, ["paths_favored", "paths_total", "unique_crashes", "unique_hangs", "bitmap_cvg", "execs_per_sec"], ["paths_favored", "paths_total", "unique_crashes", "unique_hangs", "bitmap_cvg", "execs_per_sec"], out=sfile)
