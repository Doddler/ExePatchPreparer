macro _invoke proc,[arg]
 { common
    if ~ arg eq
   reverse
     pushd arg
   common
    end if
   call dword [proc] }


macro _invoke_cdecl proc,[arg]
 {
   common
    .args_c=0
    if ~ arg eq
   reverse
     pushd arg
     .args_c = .args_c+1
   common
    end if
   call dword [proc]
   if .args_c > 0
   add esp, .args_c*4
   end if }

macro _call_cdecl proc,[arg]
 {
   common
    .args_c=0
    if ~ arg eq
   reverse
     pushd arg
     .args_c = .args_c+1
   common
    end if
   call proc
   if .args_c > 0
   add esp, .args_c*4
   end if }


; === Patching macros ===

p_savedorg = 0
p_sectionset = 0

macro pushorg value*
{
  p_wasorg = $
  org value
  p_inorg = $
  p_savedorg = 1
}

macro poporg
{
  local orgsize
  orgsize = $ - p_inorg
  org p_wasorg + orgsize
  p_savedorg = 0
}

macro patchsection value*
{
  p_sectionset = 1
  p_sectionorg = value
}

macro patchsetsection value*, address*
{
  patchsection value
  patchatfixed address
}

macro patchfile name*
{
  virtual
    @@:
    file name
    p_filesize = $ - @b
  end virtual
  p_start = $
  p_pointer = 0
  p_filename equ name
}

macro patchatfixed address*
{
  if p_savedorg = 1
    poporg
  end if

  p_pointer = p_pointer - p_start + $
  p_toadd = address - $

  if address >= 0
    if p_toadd >= 0
      if p_pointer + p_toadd <= p_filesize
        file p_filename: p_pointer, p_toadd
      else
        p_addpart = 0
        if p_pointer < p_filesize
          p_addpart = p_filesize - p_pointer
          file p_filename: p_pointer, p_addpart
        end if
        rb p_toadd - p_addpart
      end if
    else
      "Error: can't move backwards."
    end if
  else
    "Error: invalid address, must be >= 0."
  end if

  p_start = $
  p_pointer = p_pointer + p_toadd

  if p_sectionset = 1
    pushorg p_sectionorg + address
  end if

}

; Completes a function patch - fills unused space with NOPs
; makes an error if the code has exceeded the length
macro patchtillfixed endAddress*
{
    pt_curAddress = $
    ; Calculation of the address
    if p_sectionset = 1
        pt_curAddress = pt_curAddress - p_sectionorg
    end if
    
    ; checking and error output
    if pt_curAddress > endAddress
        _print_int "***ERROR*** Patch overflow error, expecting end of patch at", endAddress
        _print_int "***ERROR*** but current offset is", pt_curAddress
        error ABORTING COMPILATION
    end if
    
    ; fill with NOPs
    if pt_curAddress < endAddress
        db (endAddress - pt_curAddress) dup (090h)
    end if
    
}


macro patchat address*
{
  address2 = address - p_sectionorg
  patchatfixed address2
}

macro patchtill address*
{
  address2 = address - p_sectionorg
  patchtillfixed address2
}


macro patchend
{
  if p_savedorg
    poporg
  end if

  p_pointer = p_pointer - p_start + $
  p_toadd = p_filesize - $

  if p_toadd >= 0
    if p_pointer + p_toadd <= p_filesize
      file p_filename: p_pointer, p_toadd
    else
      p_addpart = 0
      if p_pointer < p_filesize
        p_addpart = p_filesize - p_pointer
        file p_filename: p_pointer, p_addpart
      end if
      db p_toadd - p_addpart dup 0
    end if
  end if
}


macro patchend2 endAddress*
{
  if p_savedorg
    poporg
  end if

  p_pointer = p_pointer - p_start + $
  p_toadd = p_filesize - $

  if p_toadd >= 0
    if p_pointer + p_toadd <= p_filesize
      file p_filename: p_pointer, p_toadd
    else
      p_addpart = 0
      if p_pointer < p_filesize
        p_addpart = p_filesize - p_pointer
        file p_filename: p_pointer, p_addpart
      end if
      db p_toadd - p_addpart dup 0
    end if
  end if

  if pt_curAddress < endAddress
    db (endAddress - pt_curAddress) dup (000h)
  end if
}


macro _print_int header*, integer*, usebits
{
    if usebits + 1 = 1
        bits = 32
    else
        bits = usebits
    end if
    display header
    display " "
    repeat bits/4
        d = '0' + integer shr (bits-%*4) and 0Fh
        if d > '9'
            d = d + 'A'-'9'-1
        end if
        display d
    end repeat
    display 13,10
}

macro _assertEqual got*, expected* { 
    if got <> expected
        _print_int "Got", got
        _print_int "Expected", expected
        error "not equal values"
    end if
}

; vim:ft=fasm



macro quickpatchpushfixed address*, target*
{
  patchatfixed (address)
   push target
  patchtillfixed (address + 5)
}

macro quickpatchbytefixed address*, val
{
  patchatfixed (address)
   db val
  patchtillfixed (address + 1)
}

macro quickpatchshortfixed address*, val
{
  patchatfixed (address)
   dw val
  patchtillfixed (address + 2)
}

macro quickpatchlongfixed address*, val
{
  patchatfixed (address)
   dq val
  patchtillfixed (address + 2)
}

macro quickpatchintfixed address*, val
{
  patchatfixed (address)
   dd val
  patchtillfixed (address + 4)
}

macro quickpatchpush address*, target*
{
  address2 = address - p_sectionorg
  quickpatchpushfixed address2, target
}

macro quickpatchshort address*, val
{
  address2 = address - p_sectionorg
  quickpatchshortfixed address2, val
}

macro quickpatchlong address*, val
{
  address2 = address - p_sectionorg
  quickpatchlongfixed address2, val
}

macro quickpatchint address*, val
{
  address2 = address - p_sectionorg
  quickpatchintfixed address2, val
}

macro quickpatchfloat address*, val
{
  address2 = address - p_sectionorg
  quickpatchintfixed address2, val
}

macro quickpatchbyte address*, val
{
  address2 = address - p_sectionorg
  quickpatchbytefixed address2, val
}

macro quickzerodw address*
{
  address2 = address - p_sectionorg
  patchatfixed (address)
   db 0,0
  patchtillfixed (address + 2)
}

macro pushall
{
  push eax
  push ebx
  push ecx
  push edx
}

macro popall
{
  pop edx
  pop ecx
  pop ebx
  pop eax
}