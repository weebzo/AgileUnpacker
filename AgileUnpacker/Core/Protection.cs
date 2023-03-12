using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AgileUnpacker.Core {
    internal abstract class Protection {
        public abstract string Name { get; }
        public abstract void Execute(Context context);
    }
}
