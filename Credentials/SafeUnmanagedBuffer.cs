using System;
using System.Collections.Generic;
using System.Text;
using System.Security;
using System.Security.Permissions;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

namespace Evb.Runtime.InteropServices
{
    internal class SafeUnmanagedBuffer : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid
    {
        private int _size;

        private SafeUnmanagedBuffer() : base(true) { }

        public SafeUnmanagedBuffer(int size, params byte[] values)
            : base(true)
        {
            this.AllocateHandle(size);

            _size = size;

            for (int i = 0; i < values.Length; i++)
                this[i] = values[i];
        }

        public SafeUnmanagedBuffer(IntPtr preexistingHandle, int size, bool ownsHandle)
            : base(ownsHandle)
        {
            SetHandle(preexistingHandle);

            _size = size;
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected virtual void AllocateHandle(int size)
        {
            SetHandle(Marshal.AllocHGlobal(size));
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);

            return true;
        }

        public virtual int Length { get { return _size; } }

        public byte this[int index]
        {
            get
            {
                if (IsInvalid) throw new InvalidOperationException();
                if (index < 0 || index >= Length) throw new ArgumentOutOfRangeException("index");

                return Marshal.ReadByte(handle, index);
            }
            set
            {
                if (IsInvalid) throw new InvalidOperationException();
                if (index < 0 || index >= Length) throw new ArgumentOutOfRangeException("index");

                Marshal.WriteByte(handle, index, value);
            }
        }

        public byte[] ToArray()
        {
            byte[] buffer = new byte[_size];

            for (int i = 0; i < _size; i++)
                buffer[i] = Marshal.ReadByte(handle, i);

            return buffer;
        }

        public char[] ToCharsArray(Encoding encoding)
        {
            byte[] bytes = ToArray();
            char[] buffer = encoding.GetChars(bytes);

            return buffer;
        }
    }
}