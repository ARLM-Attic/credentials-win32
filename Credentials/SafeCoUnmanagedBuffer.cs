using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace Evb.Runtime.InteropServices
{
    internal class SafeCoUnmanagedBuffer : SafeUnmanagedBuffer
    {
        public SafeCoUnmanagedBuffer(int size, params byte[] values)
            : base(size, values) { }

        public SafeCoUnmanagedBuffer(IntPtr preexistingHandle, int size, bool ownsHandle)
            : base(preexistingHandle, size, ownsHandle) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override void AllocateHandle(int size)
        {
            SetHandle(Marshal.AllocCoTaskMem(size));
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle()
        {
            Marshal.FreeCoTaskMem(handle);

            return true;
        }
    }
}
