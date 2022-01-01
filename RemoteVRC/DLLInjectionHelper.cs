using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;

namespace RemoteVRC;

public class DLLInjectionHelper
    {
        //////////////////////////////////////////////////////////////////////////////////////////////////// Import
        ////////////////////////////////////////////////////////////////////////////////////////// Static
        //////////////////////////////////////////////////////////////////////////////// Private

        #region 마지막 에러 코드 구하기 - GetLastError()

        /// <summary>
        /// 마지막 에러 코드 구하기
        /// </summary>
        /// <returns>마지막 에러 코드</returns>
        [DllImport("kernel32.dll")]
        private static extern uint GetLastError();

        #endregion
        #region 프로세스 열기 - OpenProcess(desiredAccess, inheritHandle, processID)

        /// <summary>
        /// 프로세스 열기
        /// </summary>
        /// <param name="desiredAccess">희망 액세스</param>
        /// <param name="inheritHandle">상속 핸들</param>
        /// <param name="processID">프로세스 ID</param>
        /// <returns>프로세스 핸들</returns>
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int desiredAccess, bool inheritHandle, int processID);

        #endregion
        #region 모듈 핸들 구하기 - GetModuleHandle(moduleName)

        /// <summary>
        /// 모듈 핸들 구하기
        /// </summary>
        /// <param name="moduleName">모듈명</param>
        /// <returns>모듈 핸들</returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        #endregion
        #region 프로세스 주소 구하기 - GetProcAddress(moduleHandle, processName)

        /// <summary>
        /// 프로세스 주소 구하기
        /// </summary>
        /// <param name="moduleHandle">모듈 핸들</param>
        /// <param name="processName">프로세스명</param>
        /// <returns>프로세스 주소 핸들</returns>
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr moduleHandle, string processName);

        #endregion
        #region 가상 메모리 할당하기 (확장) - VirtualAllocEx(processHandle, addressHandle, size, allocationType, protect)

        /// <summary>
        /// 가상 메모리 할당하기 (확장)
        /// </summary>
        /// <param name="processHandle">프로세스 핸들</param>
        /// <param name="addressHandle">주소 핸들</param>
        /// <param name="size">크기</param>
        /// <param name="allocationType">할당 타입</param>
        /// <param name="protect">보호 여부</param>
        /// <returns>가상 메모리 핸들</returns>
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx
        (
            IntPtr processHandle,
            IntPtr addressHandle,
            uint   size,
            uint   allocationType,
            uint   protect
        );

        #endregion
        #region 프로세스 메모리 쓰기 - WriteProcessMemory(processHandle, baseAddressHandle, bufferByteArray, size, byteCountWritten)

        /// <summary>
        /// 프로세스 메모리 쓰기
        /// </summary>
        /// <param name="processHandle">프로세스 핸들</param>
        /// <param name="baseAddressHandle">베이스 주소 핸들</param>
        /// <param name="bufferByteArray">버퍼 바이트 배열</param>
        /// <param name="size">크기</param>
        /// <param name="byteCountWritten">쓴 바이트 수</param>
        /// <returns>처리 결과</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory
        (
            IntPtr      processHandle,
            IntPtr      baseAddressHandle,
            byte[]      bufferByteArray,
            uint        size,
            out UIntPtr byteCountWritten
        );

        #endregion
        #region 원격 스레드 생성하기 - CreateRemoteThread(processHandle, threadAttributeHandle, stackSize, startAddressHandle, parameter, creationFlag, threadID)

        /// <summary>
        /// 원격 스레드 생성하기
        /// </summary>
        /// <param name="processHandle">프로세스 핸들</param>
        /// <param name="threadAttributeHandle">스레드 어트리뷰트</param>
        /// <param name="stackSize">스택 크기</param>
        /// <param name="startAddressHandle">시작 주소 핸들</param>
        /// <param name="parameter">매개 변수</param>
        /// <param name="creationFlag">생성 플래그</param>
        /// <param name="threadID">스레드 ID</param>
        /// <returns>스레드 핸들</returns>
        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread
        (
            IntPtr processHandle,
            IntPtr threadAttributeHandle,
            uint   stackSize,
            IntPtr startAddressHandle,
            IntPtr parameter,
            uint   creationFlag,
            IntPtr threadID
        );

        #endregion

        //////////////////////////////////////////////////////////////////////////////////////////////////// Field
        ////////////////////////////////////////////////////////////////////////////////////////// Private

        #region Field

        /// <summary>
        /// PROCESS_CREATE_THREAD
        /// </summary>
        private const int PROCESS_CREATE_THREAD = 0x0002;

        /// <summary>
        /// PROCESS_QUERY_INFORMATION
        /// </summary>
        private const int PROCESS_QUERY_INFORMATION = 0x0400;

        /// <summary>
        /// PROCESS_VM_OPERATION
        /// </summary>
        private const int PROCESS_VM_OPERATION = 0x0008;

        /// <summary>
        /// PROCESS_VM_WRITE
        /// </summary>
        private const int PROCESS_VM_WRITE = 0x0020;

        /// <summary>
        /// PROCESS_VM_READ
        /// </summary>
        private const int PROCESS_VM_READ = 0x0010;

        /// <summary>
        /// MEM_COMMIT
        /// </summary>
        private const uint MEM_COMMIT = 0x00001000;

        /// <summary>
        /// MEM_RESERVE
        /// </summary>
        private const uint MEM_RESERVE = 0x00002000;

        /// <summary>
        /// PAGE_READWRITE
        /// </summary>
        private const uint PAGE_READWRITE = 4;

        #endregion

        //////////////////////////////////////////////////////////////////////////////////////////////////// Constructor
        ////////////////////////////////////////////////////////////////////////////////////////// Public

        #region 생성자 - DLLInjectionHelper()

        /// <summary>
        /// 생성자
        /// </summary>
        public DLLInjectionHelper()
        {
        }

        #endregion

        //////////////////////////////////////////////////////////////////////////////////////////////////// Method
        ////////////////////////////////////////////////////////////////////////////////////////// Public

        #region 주입하기 - Inject(processID, dllFilePath)

        /// <summary>
        /// 주입하기
        /// </summary>
        /// <param name="processID">프로세스 ID</param>
        /// <param name="dllFilePath">DLL 파일 경로</param>
        /// <returns>처리 결과</returns>
        public bool Inject(int processID, string dllFilePath)
        {
            IntPtr threadProcessHandle;
            IntPtr processHandle      = IntPtr.Zero;
            IntPtr threadHandle       = IntPtr.Zero;
            IntPtr remoteBufferHandle = IntPtr.Zero;
            uint   bufferSize         = (uint)((dllFilePath.Length + 1) * Marshal.SizeOf(typeof(char)));
           
            processHandle = OpenProcess
            (
                PROCESS_CREATE_THREAD     |
                PROCESS_QUERY_INFORMATION |
                PROCESS_VM_OPERATION      |
                PROCESS_VM_WRITE          |
                PROCESS_VM_READ,
                false,
                processID
            );

            if(processHandle == IntPtr.Zero)
            {
                MessageBox.Show("OpenProcess Error : " + GetLastError());

                return false;
            }

            remoteBufferHandle = VirtualAllocEx(processHandle, IntPtr.Zero, bufferSize, MEM_COMMIT, PAGE_READWRITE);

            UIntPtr byteCountWritten;

            WriteProcessMemory
            (
                processHandle,
                remoteBufferHandle,
                Encoding.Default.GetBytes(dllFilePath),
                bufferSize,
                out byteCountWritten
            );

            threadProcessHandle = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            CreateRemoteThread(processHandle, IntPtr.Zero, 0, threadProcessHandle, remoteBufferHandle, 0, IntPtr.Zero);

            return true;
        }

        public bool injection(Int32 pid, string dllPath)
        {
            IntPtr pThreadProc;
            IntPtr hProcess = IntPtr.Zero, hThread = IntPtr.Zero;
            IntPtr pRemoteBuffer = IntPtr.Zero;
            uint bufferSize =(uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char)));
           
            hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false,pid);
            if (hProcess == IntPtr.Zero)
            {
                MessageBox.Show("openprocess error!:" + GetLastError());
                return false;
            }
            pRemoteBuffer = VirtualAllocEx(hProcess, IntPtr.Zero, bufferSize, MEM_COMMIT, PAGE_READWRITE);
            UIntPtr written;
            WriteProcessMemory(hProcess, pRemoteBuffer, Encoding.Default.GetBytes(dllPath), bufferSize,out written);
            pThreadProc = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, pThreadProc, pRemoteBuffer, 0, IntPtr.Zero);
            return true;
        }
        #endregion
        #region 꺼내기 - Eject(processID, dllFilePath)

        /// <summary>
        /// 꺼내기
        /// </summary>
        /// <param name="processID">프로세스 ID</param>
        /// <param name="dllFilePath">DLL 파일 경로</param>
        /// <returns>처리 결과</returns>
        private bool Eject(int processID, string dllFilePath)
        {
            IntPtr  processHandle         = IntPtr.Zero;
            IntPtr  functionAddressHandle = GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary");
            IntPtr  baseAddressHandle     = IntPtr.Zero;
            uint    bufferSize            = (uint)((dllFilePath.Length + 1) * Marshal.SizeOf(typeof(char)));
            bool    found                 = false;

            Process                 process                 = Process.GetProcessById(processID);
            ProcessModuleCollection processModuleCollection = process.Modules;

            processHandle = OpenProcess
            (
                PROCESS_CREATE_THREAD     |
                PROCESS_QUERY_INFORMATION |
                PROCESS_VM_OPERATION      |
                PROCESS_VM_WRITE          |
                PROCESS_VM_READ,
                false,
                processID
            );

            if(processHandle == IntPtr.Zero)
            {
                MessageBox.Show("OpenProcess Error : " + GetLastError());

                return false;
            }

            for(int i = 0; i < processModuleCollection.Count; i++)
            {
                if(processModuleCollection[i].FileName.Contains(dllFilePath))
                {
                    baseAddressHandle = processModuleCollection[i].BaseAddress;

                    found = true;
                    
                    break;
                }
            }

            if(found == false)
            {
                MessageBox.Show("DLL not found");

                return false;
            }

            CreateRemoteThread
            (
                processHandle,
                IntPtr.Zero,
                0,
                functionAddressHandle,
                baseAddressHandle,
                0,
                IntPtr.Zero
            );

            return true;  
        }

        #endregion
    }