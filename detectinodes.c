#include <Python.h> // python-c API
//#include <python3.5m/Python.h> 
#include <wchar.h>

#define PYTHON_FILENAME "hidden-inode-detector.py"

int hideinodedetector(void);

int hideinodedetector(void){

    int return_value = 0;

    int python_argc = 5;
    const char* python_argv[] = {PYTHON_FILENAME, "/dev/sda1", "/", "/", ""}; // python3 hidden-inode-detector.py /dev/sda1 / /

    wchar_t arg0[100];
    mbstowcs(arg0, python_argv[0], 100); // Converts char* to wchar_t*
    wchar_t arg1[100]; //PYTHON_FILENAME
    mbstowcs(arg1, python_argv[1], 100);
    wchar_t arg2[100];
    mbstowcs(arg2, python_argv[2], 100);
    wchar_t arg3[100];
    mbstowcs(arg3, python_argv[3], 100);
    wchar_t arg4[100];
    mbstowcs(arg4, python_argv[4], 100);

    wchar_t* python_argv_converted[] = {arg0, arg1, arg2, arg3, arg4}; // used in PySys_SetArgv
    
    Py_SetProgramName(arg0);
    FILE* fp;
    Py_Initialize();

    PySys_SetArgv(python_argc, python_argv_converted);

    fp = _Py_fopen(python_argv[0], "r");
    if (fp == NULL){
        return_value = -1;
        printf("filedirdetector.c: Python FILE* object is not created\n");
        return return_value;
    }

    return_value = PyRun_SimpleFile(fp, python_argv[0]); // executes hidden-inode-detector.py
    if (return_value < 0){
        printf("filedirdetector.c: Python script hidden-inode-detector.py has raised an exception. Hidden inode scan is incomplete.\n");
        return return_value;
    }

    Py_Finalize();
    return return_value;
}

