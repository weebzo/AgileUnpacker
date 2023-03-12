using AgileUnpacker.Core;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace AgileUnpacker.Protections {
    internal class RestoreCalls : Protection {
        public override string Name => nameof(RestoreCalls);

        public override void Execute(Context context) {
            var module = context.Module;
            int searchToken = 0;
            var moduleHandle = context.Asm.ManifestModule.ModuleHandle;
            var importedMethods = new Dictionary<MethodBase, IMethodDescriptor>();
            var processedDelegates = new Dictionary<TypeDefinition, IMethodDescriptor>();
            TypeDefinition mainProxyType = null;
            Console.WriteLine("Looking for proxy types...");

            foreach(var type in module.TopLevelTypes) {
                if(type.BaseType == null)
                    continue;
                if(type.BaseType.Name.Contains("MulticastDelegate")) {
                    foundProxies++;
                    var delegateField = type.Fields[0];
                    var cctor = type.GetStaticConstructor();
                    var setupCall = cctor.CilMethodBody.Instructions.First(x => x.OpCode == CilOpCodes.Call).Operand as MethodDefinition;
                    var setupCallInstrs = setupCall.CilMethodBody.Instructions;
                    mainProxyType = setupCall.DeclaringType;
                    if(searchToken == 0) {
                        for(int j = 0; j < setupCallInstrs.Count; j++) {
                            var setupInstr = setupCall.CilMethodBody.Instructions[j];
                            if(!setupInstr.IsLdcI4())
                                continue;
                            if(setupCallInstrs[j - 1].OpCode == CilOpCodes.Ldloc_S && setupCallInstrs[j - 2].OpCode == CilOpCodes.Ldsflda) {
                                searchToken = setupInstr.GetLdcI4Constant();
                                break;
                            }
                        }
                    }
                    if(searchToken != 0) {
                        var token = GetToken(delegateField.Name, out var isvirt) + searchToken;
                        var methodinfo = MethodBase.GetMethodFromHandle(moduleHandle.ResolveMethodHandle((int)token));
                        IMethodDescriptor refer = importedMethods.ContainsKey(methodinfo) ? importedMethods[methodinfo] : module.DefaultImporter.ImportMethod(methodinfo);
                        if(!importedMethods.ContainsKey(methodinfo))
                            importedMethods.Add(methodinfo, refer);
                        processedDelegates.Add(type, refer);
                        Console.WriteLine($"Found proxy\n Name: {type.Name}\n Token: {type.MetadataToken.ToInt32()}\n Actual Method: {refer.Name}");
                    }
                }
            }

            foreach(var type in module.TopLevelTypes) {
                foreach(var method in type.Methods.Where(x => x.CilMethodBody != null)) {
                    var instrs = method.CilMethodBody.Instructions;
                    for(int i = 0; i < instrs.Count; i++) {
                        var instr = instrs[i];
                        if(instr.OpCode != CilOpCodes.Call)
                            continue;
                        var operand = instr.Operand;
                        if(operand.ToString().Contains("Invoke")) {
                            if(operand is MethodDefinition call) {
                                if(call.DeclaringType.BaseType.Name.Contains("MulticastDelegate")) {
                                    var fixedMember = processedDelegates[call.DeclaringType];
                                    var isCallVirt = call.DeclaringType.Fields[0].Name.Contains('%');
                                    instr.OpCode = isCallVirt ? CilOpCodes.Callvirt : CilOpCodes.Call;
                                    instr.Operand = fixedMember;
                                    solvedProxies++;
                                }
                            }

                        }
                    }
                    foreach(var instr in instrs) {
                        if(instr.OpCode != CilOpCodes.Ldsfld)
                            continue;
                        var fieldDef = instr.Operand as FieldDefinition;
                        if(fieldDef != null) {
                            if(fieldDef.DeclaringType.BaseType != null) {
                                if(fieldDef.DeclaringType.BaseType.Name.Contains("MulticastDelegate")) {
                                    if(processedDelegates.ContainsKey(fieldDef.DeclaringType))
                                        instr.ReplaceWithNop();
                                }
                            }
                        }
                    }
                }
            }
            foreach(var proxyType in processedDelegates.Keys) {
                module.TopLevelTypes.Remove(proxyType);
            }
            if(mainProxyType != null) {
                module.TopLevelTypes.Remove(mainProxyType);
            }
            Console.WriteLine($"Fixed {solvedProxies} proxies");
        }

        private uint GetToken(string name, out bool isCallVirt) {
            isCallVirt = name.EndsWith("%");
            string newName = isCallVirt ? name.TrimEnd('%') : name;
            return BitConverter.ToUInt32(Convert.FromBase64String(newName), 0);
        }

        private int foundProxies = 0;
        private int solvedProxies = 0;
    }
}
