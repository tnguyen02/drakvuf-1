#include "libdrakvuf.h"

static int pidTracker[100];
static bool inject_finished = false;

static inline void update_pid_tracker(drakvuf_t drakvuf, const char* name, int pid, int ppid){
    drakvuf_pause(drakvuf);
    //Add parent sample pid to tracker
    if (strstr(name, "sample") != 0 || strstr(name, "malwar") != 0 || strstr(name, "MALWAR") != 0){
        bool exist = false;

        for (size_t i = 0; i < sizeof(pidTracker)/sizeof(pidTracker[0]); i++) {
            if (pidTracker[i] == pid) {
                inject_finished = true;
                exist = true;
                break;
            }
        }

        if(exist == false){
            for (size_t i = 0; i < sizeof(pidTracker)/sizeof(pidTracker[0]); i++) {
                if (pidTracker[i] == 0) {
                    pidTracker[i] = pid;
                    inject_finished = true;
                    break;
                }
            } 
        }
    }

    //add any child pid to tracker
    if (ppid != 0 && ppid != 4){
        bool hasParent = false;
        bool trackingChildAlready = false;

        for (size_t i = 0; i < sizeof(pidTracker)/sizeof(pidTracker[0]); i++) {
            if (pidTracker[i] == pid) {
                trackingChildAlready = true;
                break;
            }
        }

        if (trackingChildAlready == false) {
            for (size_t i = 0; i < sizeof(pidTracker)/sizeof(pidTracker[0]); i++) {
                if (pidTracker[i] == ppid) {
                    hasParent = true;
                    break;
                }
            }

            if(hasParent == true){
                for (size_t i = 0; i < sizeof(pidTracker)/sizeof(pidTracker[0]); i++) {
                    if (pidTracker[i] == 0) {
                        pidTracker[i] = pid;
                        break;
                    }
                } 
            }
        }
    }

    drakvuf_resume(drakvuf);
}