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

Lemma wrapI_unchanged:
  forall minInt maxInt x,
  minInt <= x <= maxInt ->
  minInt <= 0 <= maxInt ->
  wrapI minInt maxInt x = x.
Proof.
  intros.
  unfold wrapI.
  pose (q := (if 0 <=? x then 0 else -1)).
  pose (del := (maxInt - minInt + 1)).
  assert (x / del = q) as div_eq.
  - assert (q <= x / del < q + 1).
    + destruct (0 <=? x) eqn: x_pos.
      * rewrite Z.leb_le in *.
        unfold q, del.
        constructor.
        -- apply Z.div_le_lower_bound; lia.
        -- apply Z.div_lt_upper_bound; lia.
      * rewrite Z.leb_gt in *.
        unfold q, del.
        constructor.
        -- apply Z.div_le_lower_bound; lia.
        -- apply Z.div_lt_upper_bound; lia.
    + lia.
  - rewrite Z.mod_eq by lia.
    unfold del in div_eq.
    rewrite div_eq.
    unfold q.
    destruct (0 <=? x) eqn: x_pos.
    + rewrite Zle_imp_le_bool by lia.
      lia.
    + assert (forall {A : Type} p (x y : A), p = false ->
        (if p then x else y) = y) as if_false.
      * intros.
        (rewrite H1; auto).
      * rewrite if_false; lia.
Qed.
