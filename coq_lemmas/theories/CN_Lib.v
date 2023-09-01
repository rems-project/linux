Require List.
Require Import ZArith Bool.
Require Import Lia.
Require NArith.
Require BinNums.

Open Scope Z.

Fixpoint count_trailing_zeroes_pos (p : BinNums.positive) : nat :=
  match p with
  | BinNums.xH => (0)%nat
  | BinNums.xO q => (count_trailing_zeroes_pos q + 1)%nat
  | BinNums.xI q => (0)%nat
  end.

Definition count_trailing_zeroes_z (z : Z) : Z :=
  match z with
  | BinNums.Z0 => 0
  | BinNums.Zpos p => Z.of_nat (count_trailing_zeroes_pos p)
  | BinNums.Zneg p => Z.of_nat (count_trailing_zeroes_pos p)
  end.

Definition find_first_set_z (z : Z) : Z :=
  if z =? 0
  then 0
  else (count_trailing_zeroes_z z + 1).

Definition wrapI (minInt : Z) (maxInt : Z) x : Z :=
  let delta := (maxInt - minInt) + 1 in
  (* Z.modulo is guaranteed good bounds as delta > 0, see Z.mod_pos_bound *)
  let y := Z.modulo x delta in
  if y <=? maxInt
  then y
  else y - delta.

Lemma wrapI_unsigned:
  forall maxInt x,
  0 <= maxInt ->
  wrapI 0 maxInt x = Z.modulo x (maxInt + 1).
Proof.
  intros.
  unfold wrapI.
  rewrite Z.sub_0_r.
  pose (bounds := Z.mod_pos_bound x (maxInt + 1)).
  destruct bounds.
  - lia.
  - rewrite Zle_imp_le_bool.
    + reflexivity.
    + lia.
Qed.


