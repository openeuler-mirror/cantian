
typedef enum 
{
    LVOS_CLOCK_REALTIME,
    LVOS_CLOCK_MONOTONIC,
    LVOS_CLOCK_PROCESS_CPUTIME_ID,
    LVOS_CLOCK_THREAD_CPUTIME_ID
}LVOS_clockid_t;

typedef int LVOS_timer_t;
typedef int pthread_attr_t;

union sigval
{
    int sival_int;
    void *sival_ptr;
};

typedef struct LVOS_sigevent
{
    int sigev_notify;
    int sigev_signo;
    union sigval sigev_value;
    void (*sigev_notify_function)(union sigval);
    pthread_attr_t *sigev_notify_attributtes;
} LVOS_sigevent_t;

typedef struct timerspec
{
    int tv_sec;
    long tv_nsec;
} timerspec_t;


typedef struct LVOS_itimerspec
{
    timerspec_t it_interval;
    timerspec_t it_value; 
}LVOS_itimerspec_t;

int LVOS_timer_create(LVOS_clockid_t clock_id, LVOS_sigevent_t *evp, LVOS_timer_t *timerid);

int LVOS_timer_delete(LVOS_timer_t timerid);

int LVOS_timer_settime(LVOS_timer_t timerid, int flags, const LVOS_itimerspec_t *new_value, LVOS_itimerspec_t *old_value);

int LVOS_timer_gettime(LVOS_timer_t timerid, LVOS_itimerspec_t *curr_value);

int LVOS_timer_getoverrun(LVOS_timer_t timerid);
