using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.IO;
using System.Reflection;

namespace ExePatchPreparer
{
    class Program
    {
        struct ExeSection
        {
            public string Name;
            public string Code;
            public int VOffset;
            public int VSize;
            public int ROffset;
            public int RSize;
            public uint Flags;
        }

        public static int RoundToAlignment(int address, int align)
        {
            var remainder = address % align;
            if (remainder == 0)
                return address;
            return address - remainder + align;
        }

        public static (bool success, string error) CreateExePatchFile(string exePath, string asmPath)
        {
            //first collect information from the exe in question
            var bytes = File.ReadAllBytes(exePath);
            var ms = new MemoryStream(bytes);
            var br = new BinaryReader(ms);
            
            ms.Seek(0x3C, SeekOrigin.Begin);
            var ntHeaderOffset = br.ReadInt32();

            ms.Seek(ntHeaderOffset, SeekOrigin.Begin);
            var peSignature = new string(br.ReadChars(4));
            if (peSignature != "PE\0\0")
                return (false, "Invalid PE header signature");

            ms.Seek(2, SeekOrigin.Current); //jump over IMAGE_MACHINE enum
            var sectionCount = br.ReadUInt16();

            ms.Seek(12, SeekOrigin.Current);
            var optionalSectionSize = br.ReadUInt16();
            var characteristics = br.ReadUInt16();

            //we're in the optional header now
            ms.Seek(28, SeekOrigin.Current);
            var imageBase = br.ReadUInt32();
            var sectionAlignment = br.ReadUInt32();
            ms.Seek(34, SeekOrigin.Current);
            var dllCharacteristics = br.ReadUInt16();

            //jump to section headers
            var sectionHeaderOffset = ntHeaderOffset + 24 + optionalSectionSize;

            var sections = new List<ExeSection>();

            for (var i = 0; i < sectionCount; i++)
            {
                ms.Seek(sectionHeaderOffset + 40 * i, SeekOrigin.Begin);
                var section = new ExeSection
                {
                    Name = new string(br.ReadChars(8)).Trim('\0'),
                    VSize = br.ReadInt32(),
                    VOffset = br.ReadInt32(),
                    RSize = br.ReadInt32(),
                    ROffset = br.ReadInt32(),
                };
                ms.Seek(12, SeekOrigin.Current);
                section.Flags = br.ReadUInt32();

                var code = section.Name.ToUpper();
                if (code.StartsWith("."))
                    code = code.Substring(1);
                while (sections.Any(s => s.Code == code)) //can happen if one section is .text and there's also a text section (no .)
                    code = "_" + code;
                section.Code = code;

                sections.Add(section);
            }

            var hasRelocations = sections.Any(s => s.Name.Contains("reloc"));

            var lastSection = sections[sectionCount - 1];

            var patchSection = new ExeSection()
            {
                Name = ".patch",
                Code = "PATCH",
                VSize = 0x10000,
                RSize = 0x10000,
                VOffset = RoundToAlignment(lastSection.VOffset + lastSection.VSize, (int)sectionAlignment),
                ROffset = RoundToAlignment(lastSection.ROffset + lastSection.RSize, (int)sectionAlignment),
            };
            sections.Add(patchSection);

            //we have the data we need, now lets generate our patch file!

            var patchText = new List<string>();
            var exeName = Path.GetFileName(exePath);

            patchText.Add("format binary as 'exe'");
            patchText.Add("use32");
            patchText.Add("");
            patchText.Add("include 'patchmacros.inc'");
            patchText.Add("");
            patchText.Add($"patchfile '{exeName}'");
            patchText.Add("");
            patchText.Add(";--------------------------------------------");
            patchText.Add("; Addressing stuff");
            patchText.Add(";--------------------------------------------");
            patchText.Add("");
            patchText.Add($"IMAGE_BASE = 0x{imageBase:X8}");

            foreach (var s in sections)
            {
                patchText.Add($"{s.Code}_VOFFSET = 0x{s.VOffset:X8}");
                patchText.Add($"{s.Code}_ROFFSET = 0x{s.ROffset:X8}");
            }

            patchText.Add("");

            foreach (var s in sections)
            {
                patchText.Add($"{s.Code}_ORG = IMAGE_BASE + {s.Code}_VOFFSET - {s.Code}_ROFFSET");
            }

            patchText.Add("");
            patchText.Add($"PATCH_VSIZE = (patch_physical_size + 0x{(sectionAlignment - 1):X}) / 0x{sectionAlignment:X4} * 0x{sectionAlignment:X4}");
            patchText.Add($"IMAGE_SIZE = PATCH_VOFFSET + PATCH_VSIZE");
            patchText.Add($"PE_LOCATION = 0x{ntHeaderOffset:X4}");

            patchText.Add("");
            patchText.Add(";--------------------------------------------");
            patchText.Add("; Patch the header!");
            patchText.Add(";--------------------------------------------");
            patchText.Add("");
            if (hasRelocations)
            {
                patchText.Add(
                    ";Relocation stuff is commented out by default. Uncomment them to (try) to patch out relocations.");
                patchText.Add("");
            }
            patchText.Add("patchsection IMAGE_BASE ; === PE header ===");
            patchText.Add("");
            patchText.Add("patchatfixed PE_LOCATION + 6 ; Update number of sections");
            patchText.Add($"\tdw {sections.Count}");
            patchText.Add("");
            if (hasRelocations)
            {
                patchText.Add($";patchatfixed PE_LOCATION + 0x16 ;disable relocations");
                patchText.Add($";\tdw 0x{(characteristics | 1):X4}");
                patchText.Add("");
            }
            patchText.Add("patchatfixed PE_LOCATION + 0x50 ; Update size of image");
            patchText.Add("\tdd IMAGE_SIZE");
            patchText.Add("");
            if (hasRelocations)
            {
                patchText.Add($";patchatfixed PE_LOCATION + 0x5E ;disable dynamic base");
                patchText.Add($";\tdw 0x{(dllCharacteristics | 0x40):X4}");
                patchText.Add("");
            }
            patchText.Add($"patchatfixed PE_LOCATION + 0x18 + 0x{optionalSectionSize:X} + 0x28 * {sections.Count - 1}  ;Add .patch section");
            patchText.Add("\tdd '.pat','ch'           ; Name");
            patchText.Add("\tdd PATCH_VSIZE           ; Virtual size");
            patchText.Add("\tdd PATCH_VOFFSET         ; VOffset");
            patchText.Add("\tdd patch_physical_size   ; Physical size");
            patchText.Add("\tdd PATCH_ROFFSET         ; Physical offset");
            patchText.Add("\tdd 0,0,0                 ; Unused");
            patchText.Add("\tdd 0xE0000060            ; Attributes");
            patchText.Add("");
            patchText.Add(";--------------------------------------------");
            patchText.Add("; Patching!");
            patchText.Add(";--------------------------------------------");
            patchText.Add("");

            foreach (var s in sections)
            {
                if (s.Code == "PATCH")
                {
                    patchText.Add(";--------------------------------------------");
                    patchText.Add("; Patch Section");
                    patchText.Add(";--------------------------------------------");
                    patchText.Add("");
                }

                patchText.Add($"patchsetsection {s.Code}_ORG, {s.Code}_ROFFSET");
                patchText.Add("");
            }
            patchText.Add("patch_section_start:");
            patchText.Add("");
            patchText.Add("");
            patchText.Add(";put your own code here!");
            patchText.Add("");
            patchText.Add("");
            patchText.Add("db 0");
            patchText.Add("");
            patchText.Add("patch_section_end:");
            patchText.Add("patch_physical_size = patch_section_end - patch_section_start");
            patchText.Add("");
            patchText.Add("patchend");

            File.WriteAllLines(asmPath, patchText);

            return (true, null);
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: ExePatchPreparer.exe exename.exe");
                return;
            }
            var file = args[0];

            var basename = Path.GetFileNameWithoutExtension(file);
            var ext = Path.GetExtension(file);
            var fullpath = Path.GetDirectoryName(file);
            var patchname = $"{basename}patch";

            var asmpatch = Path.Combine(fullpath, patchname + ".asm");

            var res = CreateExePatchFile(file, asmpatch);
            if (!res.success)
            {
                Console.WriteLine($"Error: {res.error}");
                return;
            }

            var bat = new List<string>();
            bat.Add($"del \"{patchname}.exe\"");
            bat.Add($"FASM.exe \"{patchname}.asm\"");
            bat.Add("pause");

            File.WriteAllLines(Path.Combine(fullpath, "build.bat"), bat);

            var macropath = Path.Combine(fullpath, "patchmacros.inc");

            if (!File.Exists(macropath))
            {
                var stream = Assembly.GetExecutingAssembly()
                    .GetManifestResourceStream("ExePatchPreparer.patchmacros.inc");

                using (var macrostream = new FileStream(macropath, FileMode.Create))
                {
                    stream.CopyTo(macrostream);
                    macrostream.Close();
                }
            }

        }
    }
}
