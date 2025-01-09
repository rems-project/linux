/* CN specification for the allocator.

   FIXME: For now, we assume an unrealistic, over-simplified allocator
   specification. For instance, the following assumes that the offset
   used in the hyp/phys is effectively a compile-time constant (does
   not change and does not require resource ownership to be accessed.
   We also entirely omit the ownership of the allocator pool in the
   specification. Instead, we have to connect this verification to our
   previous buddy allocator verification.
*/

/*@
predicate (void) Byte(pointer p, u8 v)
{
  take v_ = Owned<char>(p);
  assert(v_ == v);
  return;
}

predicate (void) Zero_Page(pointer p)
{
    take us = each (u64 i; 0u64 <= i && i < 4096u64)
                   {Byte(array_shift<char>(p, i), 0u8)};
    return;
}

predicate {boolean exists} Cond_Zero_Page (pointer p) 
{
  if (ptr_eq (p,NULL)) {
    return {exists: false};
  }
  else {
    assert (! addr_eq(p, NULL)); //TODO: this shouldn't be needed, fix this in CN
    take u = Zero_Page(p);
    return {exists: true};
  }
}



function (u64) phys_virt_offset ()

function (boolean) valid_phys_virt_offset ()
{ 
  mod(phys_virt_offset (), 4096u64) == 0u64 
}

function (pointer) hyp_phys_to_virt (u64 phys)
{
  (pointer) (phys - phys_virt_offset ())
}

spec hyp_phys_to_virt (u64 phys);
  requires true;
  ensures  ptr_eq(return,hyp_phys_to_virt (phys));

function (u64) hyp_virt_to_phys (pointer virt)
{
  ((u64) virt) + phys_virt_offset ()
}

spec hyp_virt_to_phys (pointer virt);
  requires true;
  ensures  return == hyp_virt_to_phys (virt);



function (boolean) valid_hyp_virt_page (pointer p)
{
  mod((u64) p, 4096u64) == 0u64 
  && hyp_virt_to_phys(p) < shift_left(1u64, 48u64)
}

spec hyp_zalloc_hyp_page (pointer arg);
  requires true;
  ensures  take P = Cond_Zero_Page (return);
           valid_hyp_virt_page(return);

spec hyp_get_page (pointer arg);
  requires true;
  ensures  true;
@*/


/*for tree carver*/ void include_allocator_spec(void) {}
