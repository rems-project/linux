Require CN_Lemmas.Gen_Spec.
Require Import ZArith.
Require Import Lia.
Import Bool.

Import Gen_Spec.Types.

Open Scope Z.

Module Dummy_Inst.

  Definition is_table_entry (encoded : Z) : bool := false.

  Definition is_valid_pte_entry (encoded : Z) : bool := false.

End Dummy_Inst.

Module Dummy_Defs := Gen_Spec.Defs (Dummy_Inst).

Module Inst.

  Definition is_table_entry (encoded : Z) : bool :=
    negb (Dummy_Defs.kvm_pte_table encoded 0 =? 0).

  Definition is_valid_pte_entry (encoded : Z) : bool :=
    negb (Dummy_Defs.kvm_pte_valid encoded =? 0).

End Inst.

Module Defs := Gen_Spec.Defs (Inst).

Module InstOK: Gen_Spec.Lemma_Spec(Inst).

Module D := Gen_Spec.Defs (Inst).

Import Inst D.

Ltac split_if nm :=
  match goal with |- context [if ?P then _ else _] =>
    destruct P eqn: nm
  end.

Lemma dummy_pte_valid_cases:
  forall pte,
  Dummy_Defs.kvm_pte_valid pte = 0 \/
  Dummy_Defs.kvm_pte_valid pte = 1.
Proof.
  intro.
  unfold is_valid_pte_entry, Dummy_Defs.kvm_pte_valid.
  split_if x; lia.
Qed.

Lemma is_valid_pte_entry_dummy_eq:
  forall pte,
  Is_true (is_valid_pte_entry pte) ->
  Dummy_Defs.kvm_pte_valid pte = 1.
Proof.
  intro.
  unfold is_valid_pte_entry.
  destruct (dummy_pte_valid_cases pte); rewrite H; cbn; lia.
Qed.

Lemma table_entry_is_valid: table_entry_is_valid_type.
  unfold table_entry_is_valid_type.
  intros.
  destruct (Inst.is_valid_pte_entry encoded) eqn: is_valid.
  - destruct (Inst.is_table_entry encoded) eqn: is_table; cbn; trivial.
  - unfold Inst.is_table_entry, Dummy_Defs.kvm_pte_table.
    unfold Inst.is_valid_pte_entry in is_valid.
    rewrite Bool.negb_false_iff in is_valid.
    apply Z.eqb_eq in is_valid.
    rewrite (CN_Lib.wrapI_unchanged _ _ _ H) by lia.
    rewrite is_valid.
    cbn.
    auto.
Qed.

Lemma kvm_pte_valid_is_valid: kvm_pte_valid_is_valid_type.
Proof.
  unfold kvm_pte_valid_is_valid_type.
  intro.
  unfold is_valid_pte_entry, kvm_pte_valid, Dummy_Defs.kvm_pte_valid.
  split_if x; auto.
Qed.

Lemma if_fun_distrib:
  forall {A B : Type} (f : A -> B) (t : bool) x y,
  f (if t then x else y) = (if t then f x else f y).
Proof.
  intros.
  destruct t; auto.
Qed.

Lemma if_if_eqb_distrib:
  forall {A : Type} (t : bool) (x y r : Z) (x2 y2 : A),
  (if (if t then x else y) =? r then x2 else y2) =
  (if t then (if x =? r then x2 else y2)
    else (if y =? r then x2 else y2)).
Proof.
  destruct t; auto.
Qed.

Lemma kvm_pte_table_is_table: kvm_pte_table_is_table_type.
Proof.
  unfold kvm_pte_table_is_table_type, valid_pgtable_level.
  intros.
  apply andb_prop_elim in H.
  destruct H as [level_lower level_upper].
  apply Is_true_eq_true in level_lower.
  apply Is_true_eq_true in level_upper.
  rewrite Z.leb_le in *.
  unfold kvm_pte_table, is_table_entry, Dummy_Defs.kvm_pte_table.
  rewrite (CN_Lib.wrapI_unchanged _ _ 0) by lia.
  cbn.
  repeat ((rewrite if_if_eqb_distrib || rewrite if_negb
    || rewrite (if_fun_distrib (CN_Lib.wrapI _ _))); cbn).
  assert (forall x, kvm_pte_valid x = Dummy_Defs.kvm_pte_valid x)
    as dummy_eq by (intros; reflexivity).
  repeat (rewrite dummy_eq).
  destruct (level =? -1) eqn: level_eq.
  - rewrite Z.eqb_eq in level_eq.
    rewrite level_eq.
    cbn.
    split_if x; auto.
  - rewrite CN_Lib.wrapI_unchanged by lia.
    split_if x; auto; lia.
Qed.

Lemma pow_2_less_64: pow_2_less_64_type.
Proof.
  unfold pow_2_less_64_type.
  intros.
  pose (Z.pow_le_mono_r 2 0 i).
  pose (Z.pow_lt_mono_r 2 i 64).
  lia.
Qed.

Lemma land_le_l:
  forall x y, 0 <= x -> Z.land x y <= x.
Proof.
  intros.
  assert (Z.land x y + Z.land x (Z.lnot y) = x).
  - rewrite Z.add_nocarry_lxor.
    + apply Z.bits_inj'; intros.
      rewrite Z.lxor_spec, Z.land_spec, Z.land_spec, Z.lnot_spec by lia.
      destruct (Z.testbit x n); destruct (Z.testbit y n); auto.
    + apply Z.bits_inj'; intros.
      rewrite Z.land_spec, Z.land_spec, Z.land_spec, Z.lnot_spec, Z.testbit_0_l by lia.
      destruct (Z.testbit x n); destruct (Z.testbit y n); auto.
  - pose (Z.land_nonneg x (Z.lnot y)).
    lia.
Qed.

Lemma bw_and_le: bw_and_le_type.
Proof.
  unfold bw_and_le_type.
  intros.
  repeat constructor.
  - rewrite Z.land_nonneg.
    auto.
  - apply land_le_l.
    auto.
  - rewrite Z.land_comm.
    auto using land_le_l.
Qed.

Lemma bw_ffs_uf_2: bw_ffs_uf_2_type.
Proof.
  unfold bw_ffs_uf_2_type.
  cbn.
  lia.
Qed.

Lemma bw_and_facts: bw_and_facts_type.
Proof.
  unfold bw_and_facts_type.
  cbn.
  lia.
Qed.

End InstOK.

