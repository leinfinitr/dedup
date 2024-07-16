# File System Mutation

**This project from the original authors of the paper "Generating Realistic Datasets for Deduplication Analysis" describes the steps to mutate the snapshots synthetically. The original paper can be found at the following link:**

**https://www.usenix.org/system/files/conference/atc12/atc12-final129.pdf**

## Installation

```bash
# Clone the repository:
$ git clone https://github.com/leinfinitr/dedup
$ cd dedup
# Generate Makefile:
$ chmod a+x configure
$ ./configure
# Build the tools:
$ make
# Install the tools:
$ make install
```

## Introduction

This file lists the steps to mutate the snapshots. Before starting the mutation, the following items must be available:

1. Results of analysis of the original snapshots
2. Hash file of the _first_ original snapshot (s0.hash)

For the convenience of explanation, let us make the following assumptions:

1. Total number of snapshots analyzed = 8
2. Results of the original snapshots analysis are in directory `/tmp/orig/`
3. Empty directory to save profiles is `/tmp/profiles/`
4. Empty directory to save fstree objects is `/tmp/pfs/`
5. Empty directory to save SQL imports of synthesized data: `/tmp/imports/`
6. Empty directory to hold logs of mutation: `/tmp/logs/`

Snapshots, corresponding profiles, fstree objects, and SQL imports are named as follows (no renaming of existing files is required):

| Snapshot | Name of Snapshot | Profile       | Fstree | SQL    | Log File |
|----------|------------------|---------------|--------|--------|----------|
|    1     |    s0            | None          | s0.pfs | s0.imp | s0.log   |
|    2     |    s1            | s1.*.profile | s1.pfs | s1.imp | s1.log   |
|    3     |    s2            | s2.*.profile | s2.pfs | s2.imp | s2.log   |
|    4     |    s3            | s3.*.profile | s3.pfs | s3.imp | s3.log   |
|    5     |    s4            | s4.*.profile | s4.pfs | s4.imp | s4.log   |
|    6     |    s5            | s5.*.profile | s5.pfs | s5.imp | s5.log   |
|    7     |    s6            | s6.*.profile | s6.pfs | s6.imp | s6.log   |
|    8     |    s7            | s7.*.profile | s7.pfs | s7.imp | s7.log   |

Note: "*" in profile name indicates some suffix identifying the dataset. s0 does not require any profile to get a populated fstree object. The populated fstree object of the initial snapshot s0 is prepared using the hash file and not via mutation.

Mutation requires first preparatory stage of creating mutation profiles. This is quick step and requires item 1 listed above.

## Preparatory Stage: Creating Mutation Profiles

1. For generating 8 snapshots synthetically, we need 7 profiles to be created from the results obtained from the original analysis.Remember that initial populated fstree object can be prepared using "hash2fstree" binary as explained later in this document.
2. A script can be used to generate all 7 profiles out of the results obtained from the original analysis:

    Location: `TOP_DIR/scripts/analysis/create_profile.sh`

    The script is invoked as follows:

    ```bash
    $ ./create_profile.sh /tmp/orig /tmp/profiles 7 8192 <some_suffix>
    ```

    where, 7 is the number of profiles to generate and 8192 is an average chunk size in bytes to use during mutation.
    `<some_suffix>` is an arbitrary string used to identify your set of profiles.if you happen to crate different kinds of profiles in the same directory directory.  This argument is not critical in any way for mutation. For example, it can be "kernel", "fredvar", etc.
3. In the `/tmp/profiles` directory, you should find profile files ready with names of the form:

    - `/tmp/profiles/s1.<some_suffix>.profile`
    - `/tmp/profiles/s2.<some_suffix>.profile`
    - ...
    - `/tmp/profiles/s7.<some_suffix>.profile`

## Mutation Stage: Actual Populated Fstree Mutation

1. Create fstree object for the initial snapshot (s0) using a binary called "hash2fstree". It takes as an input a hash file and converts it to an fstree:

    ```bash
    # ./hash2fstree s0.hash
    ```

    This creates a populated fstree object with the name "s0.hash.fst". Copy it to the populated fstree object directory with a proper name:

    ```bash
    # cp ./s0.hash.fst /tmp/pfs/s0.pfs
    ```

    Generate an SQL import for analyzing synthetically generated datasets:

    ```bash
    # ./fstree-print -i /tmp/pfs/s0.pfs -s > /tmp/imports/s0.imp
    ```

2. From this step onwards, we start actual mutation. Using profile for snapshot 1 (s1), we mutate the populated fstree object of s0 to generate the populated fstree object for snapshot s1:

    ```bash
    # time ./fstree-mutate -i /tmp/pfs/s0.pfs -p /tmp/profiles/s1.<some_suffix>.profile \\
                   -o /tmp/pfs/s1.pfs > /tmp/logs/s1.log
    ```

    /tmp/pfs/s1.pfs is the new populated fstree object representing snapshot 1 (s1). We collect the log of each mutation stage and the time for mutation. Notice, that time is not recorded in the log, please, write it down for every mutation! (this allows us to measure mutation performance).

    Generate its equivalent SQL import:

    ```bash
    # ./fstree-print -i /tmp/pfs/s1.pfs -s > /tmp/imports/s1.imp
    ```

3. Continue the mutation cycle by repeating the previous step for the number of snapshots that we want to process.

4. At this point, SQL imports of all 8 synthetically generated snapshots are available. These 8 imports are ready for MySQL analysis as mentioned in the README in the dedupdb directory (`TOP_DIR/dedupdb/README`).

---

**THE BELOW ACTIONS ARE NOT NEEDED RIGHT NOW**

---

Actual creation of File System Tree out of populated Fstree object:

1. For analyzing accuracy of synthetic data, this step is NOT required, but for collecting performance numbers, we need to actually create one filesystem tree on the disk (Essentially step 4 below).

2.  This step actual creates the file system on disk and hashes of the created file system can be collected using "dedup" tool as done for original snapshots.  Once the hashes are available, SQL imports can be generated using "hfstat" tool.  These SQL imports are then loaded into MySQL database and analyzed as mentioned in TOP_DIR/dedupdb/README file.

3. Use the "fscreate" tool to create actual filesystems out of populated fstree objects:

    ```bash
    # ./fscreate -i /tmp/pfs/s0.pfs -o /tmp/s0_dir
    ```

    Actual disk representation of file system tree corresponding to s0.pfs fstree object will be created under root as /tmp/s0_dir.  Similarly, we can create file systems corresponding to each of the snapshot:

    ```bash
    # ./fscreate -i /tmp/pfs/s1.pfs -o /tmp/s1_dir
    # ./fscreate -i /tmp/pfs/s2.pfs -o /tmp/s2_dir
    ```

3. To collect the performance of the filesystem on the actual disk, use the "time" command after clearing the caches:

    ```bash
    # sync
    # echo 3 > /proc/sys/vm/drop_caches
    # time ./fscreate -i /tmp/pfs/s7.pfs -o /tmp/s7_dir
    # time sync
    ```

    Addition of last 2 "time" commands is reported in the table.