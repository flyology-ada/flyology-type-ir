with Ada.Exceptions;
with Ada.Text_IO;
with AUnit.Assertions;
with Flyology_Type_IR.Model;
with Flyology_Type_IR.Validation;

procedure Tests is
   use AUnit.Assertions;
   use Flyology_Type_IR.Model;
   use Flyology_Type_IR.Validation;

   function Known_Fact (Value : String) return Semantic_Fact is
     (Status => Known,
      Value  => (Kind => Text_Value, Text_Data => To_Text (Value)),
      Code   => To_Text (""),
      Detail => To_Text (""));

   function Known_Boolean (Value : Boolean) return Semantic_Fact is
     (Status => Known,
      Value  => (Kind => Boolean_Value, Boolean_Data => Value),
      Code   => To_Text (""),
      Detail => To_Text (""));

   function Known_Rational
     (Numerator, Denominator : String) return Semantic_Fact is
     (Status => Known,
      Value  =>
        (Kind             => Exact_Rational_Value,
         Numerator_Data   => To_Text (Numerator),
         Denominator_Data => To_Text (Denominator)),
      Code   => To_Text (""),
      Detail => To_Text (""));

   function Known_Decimal (Value : String) return Semantic_Fact is
     (Status => Known,
      Value  =>
        (Kind         => Decimal_Integer_Value,
         Decimal_Data => To_Text (Value)),
      Code   => To_Text (""),
      Detail => To_Text (""));

   function Unknown_Fact return Semantic_Fact is
     (Status => Unknown,
      Value  => (Kind => Text_Value, Text_Data => To_Text ("")),
      Code   => To_Text ("analysis_incomplete"),
      Detail => To_Text ("fixture"));

   function Unknown_With_Hidden_Value return Semantic_Fact is
     (Status => Unknown,
      Value  => (Kind => Boolean_Value, Boolean_Data => True),
      Code   => To_Text ("analysis_incomplete"),
      Detail => To_Text ("fixture"));

   type Fact_Name_Array is array (Positive range <>) of Fact_Name;
   Required_Facts : constant Fact_Name_Array :=
     (Definite_Fact,
      Limited_Fact,
      Tagged_Fact,
      Class_Wide_Fact,
      Abstract_Fact,
      Contains_Access_Fact,
      Task_Fact,
      Protected_Fact,
      Controlled_Fact,
      Contains_Controlled_Fact,
      Predicate_Fact);

   function Has_Code
     (Diagnostics : Diagnostic_Vectors.Vector;
      Code        : Diagnostic_Code) return Boolean
   is
   begin
      for Item of Diagnostics loop
         if Item.Code = Code then
            return True;
         end if;
      end loop;
      return False;
   end Has_Code;

   Document : IR_Document;
begin
   Assert (Is_Canonical_Decimal ("0"), "zero is canonical");
   Assert (Is_Canonical_Decimal ("-42"), "negative integer is canonical");
   Assert (Is_Canonical_Decimal ("999999999999999999999999"), "unbounded integer is canonical");
   Assert (not Is_Canonical_Decimal ("-0"), "negative zero is rejected");
   Assert (not Is_Canonical_Decimal ("01"), "leading zero is rejected");
   Assert (not Is_Canonical_Decimal ("1e3"), "exponent is rejected");
   Assert (Is_Well_Formed (Known_Fact ("true")), "Known fact is exact");
   Assert
     (not Is_Compatible (Predicate_Fact, Known_Fact ("true")),
      "boolean core facts reject text values");
   Assert (Is_Well_Formed (Unknown_Fact), "Unknown fact has stable reason");
   Assert
     (not Overlay_Replacement_Allowed
       (Unknown_Fact, Known_Boolean (False)),
      "an overlay cannot replace Unknown structure with a guess");
   Assert
     (not Overlay_Replacement_Allowed
       (Known_Boolean (False), Known_Boolean (True)),
      "an overlay cannot grant visibility by changing a Known fact");
   Assert
     (Is_Well_Formed (Known_Rational ("-1", "3")),
      "exact rational uses canonical decimal strings");
   Assert
     (not Is_Well_Formed (Known_Rational ("1", "0")),
      "exact rational denominator must be positive");
   Assert
     (not Is_Well_Formed (Known_Rational ("2", "4")),
      "exact rational must be reduced to lowest terms");
   Assert
     (Is_Canonical_Semantic_ID ("decl:example.t#public"),
      "semantic ID has an explicit view suffix");
   Assert
     (not Is_Canonical_Semantic_ID ("decl:example.t"),
      "semantic ID without a view is rejected");
   Assert
     (not Is_Canonical_Semantic_ID ("decl:/tmp/example.t#public"),
      "source paths cannot enter semantic IDs");
   Assert
     (not Is_Canonical_Name ("example.x%4d%69%78%65%64"),
      "v1 rejects extended identifiers instead of inventing identity");
   Assert
     (not Is_Canonical_Name ("example.x_"),
      "Ada basic identifiers cannot end in underscore");
   Assert
     (not Is_Canonical_Name ("example.x__y"),
      "Ada basic identifiers cannot contain doubled underscores");
   Assert
     (not Is_Canonical_Name ("example.end"),
      "Ada reserved words cannot be canonical identifier segments");
   Assert
     (not Is_Canonical_Semantic_ID ("decl:example.x%ff#public"),
      "semantic IDs reject invalid UTF-8 percent encoding");
   Assert
     (not Is_Valid_UTF8 ((1 => Character'Val (16#FF#))),
      "raw malformed UTF-8 is rejected");
   Assert
     (not Is_Well_Formed (Unknown_With_Hidden_Value),
      "imprecise facts cannot carry hidden inactive values");

   Document.Required_Features.Append ("ada-type-ir/core");
   Document.Required_Features.Append ("ada-type-ir/decimal-strings");
   Document.Required_Features.Append ("ada-type-ir/exact-variants");
   Document.Required_Features.Append ("ada-type-ir/graph-refs");
   Document.Required_Features.Append ("ada-type-ir/typed-shapes");
   Document.Context.Legality_Succeeded := True;
   Document.Context.Extractor_Version := To_Text ("0.1.0");
   Document.Context.Libadalang_Version := To_Text ("26.0.0");
   Document.Context.GNAT_Version := To_Text ("26.0.0");
   Document.Context.Compiler_Path := To_Text ("/fixture/bin/gnat");
   Document.Context.Compiler_Identity := To_Text ("GNAT 26.0.0 native");
   Document.Context.Canonical_GPR_Path := To_Text ("/fixture/example.gpr");
   Document.Context.Legality_Arguments.Append ("gnat");
   Document.Context.Legality_Tool_Identity := To_Text ("GNAT 26.0.0 native");
   Document.Context.Legality_Working_Directory := To_Text ("/fixture");
   Document.Context.Project_Name := To_Text ("example");
   Document.Context.Target := To_Text ("native");
   Document.Context.Runtime := To_Text ("native:26.0.0");
   Document.Context.Consumer_Unit := To_Text ("flyology.generated");
   Document.Context.Derivation_Unit := To_Text ("example");
   Document.Context.Accessibility_Region := To_Text ("public_spec");
   Document.Context.Effective_Closure_Digest :=
     To_Text ("0000000000000000000000000000000000000000000000000000000000000000");
   Document.Context.Legality_Command_Fingerprint :=
     To_Text ("0000000000000000000000000000000000000000000000000000000000000000");
   Document.Context.Selected_Units.Append
     ((Unit_Name      => To_Text ("Example"),
       Logical_Name   => To_Text ("fixtures/ada/example.ads"),
       Source_Kind    => To_Text ("spec"),
       Content_Digest =>
         To_Text
           ("0000000000000000000000000000000000000000000000000000000000000000")));
   Document.Context.Project_Files.Append
     ((Logical_Name   => To_Text ("/fixture/example.gpr"),
       Content_Digest =>
         To_Text
           ("0000000000000000000000000000000000000000000000000000000000000000")));
   Document.Context.Runtime_Sources.Append
     ((Logical_Name   => To_Text ("runtime:ada"),
       Content_Digest =>
         To_Text
           ("0000000000000000000000000000000000000000000000000000000000000000")));
   Document.Context.Project_Closure.Append ("Example");
   Document.Context.Requested_Units.Append ("Example");
   Document.Declarations.Append
     ((Stable_ID         => To_Text ("decl:example.t#public"),
       Canonical_Name    => To_Text ("example.t"),
       Display_Name      => To_Text ("T"),
       Kind              => Signed_Integer,
       Representation_Available => Known_Boolean (True),
       Consumer_Can_Name_Components => Known_Boolean (False),
       others            => <>));
   for Name of Required_Facts loop
      Document.Declarations (0).Facts.Append
        ((Name      => Name,
          Fact      => Known_Boolean (False)));
   end loop;
   Document.Declarations (0).Facts (0).Fact := Known_Boolean (True);
   Document.Declarations (0).Constraint :=
     (Kind       => Scalar_Range_Constraint,
      Provenance => Declared_Subtype,
      Low        =>
        new Expression'
          (Kind    => Integer_Literal,
           Syntax  => To_Text ("0"),
           Literal => To_Text ("0")),
      High       =>
        new Expression'
          (Kind    => Integer_Literal,
           Syntax  => To_Text ("10"),
           Literal => To_Text ("10")),
      Staticness => Known_Boolean (True),
      Static_Low => Known_Decimal ("0"),
      Static_High => Known_Decimal ("10"),
      Predicate  => Known_Boolean (False),
      others     => <>);

   Assert
     (not Has_Errors (Validate (Document, Structural)),
      "well-formed graph passes structural validation");
   Assert
     (Has_Errors (Validate (Document, Strict_Consumer)),
      "unattested extraction contexts fail closed in strict validation");

   Document.Declarations (0).Facts (0).Fact := Known_Fact ("false");
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "core fact names enforce their value kinds");
   Document.Declarations (0).Facts (0).Fact := Known_Boolean (True);

   Document.Declarations (0).Consumer_Can_Name_Components := Unknown_Fact;
   Assert
     (not Has_Errors (Validate (Document, Structural)),
      "structural validation preserves unknown visibility");
   Assert
     (Has_Code
        (Validate (Document, Strict_Consumer),
         Imprecise_Mandatory_Fact),
      "strict validation cannot grant unknown visibility");
   Document.Declarations (0).Consumer_Can_Name_Components :=
     Known_Boolean (False);

   Assert
     (not Has_Code
        (Validate (Document, Strict_Consumer),
         Imprecise_Mandatory_Fact),
      "exact constraint facts do not add an imprecision diagnostic");
   Document.Declarations (0).Constraint.Staticness := Unknown_Fact;
   Assert
     (Has_Code
        (Validate (Document, Strict_Consumer),
         Imprecise_Mandatory_Fact),
      "strict validation rejects imprecise constraint facts");
   Document.Declarations (0).Constraint.Staticness := Known_Boolean (True);

   Document.Annotations.Append
     ((Namespace         => To_Text ("example.test"),
       Action            => To_Text ("check"),
       Target_ID         => To_Text ("decl:example.t#public"),
       Declaration_Order => 0,
       others            => <>));
   Document.Annotations (0).Arguments.Append
     ((Kind             => Exact_Rational_Value,
       Numerator_Data   => To_Text ("1"),
       Denominator_Data => To_Text ("0")));
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "annotation typed arguments are validated");
   Document.Annotations.Clear;

   declare
      Procedure_Entity : Semantic_Entity :=
        (Stable_ID =>
           To_Text
             ("decl:example.consume[profile=0:in:x:decl:example.t#public,result=none]#public"),
         Canonical_Name => To_Text ("example.consume"),
         Display_Name => To_Text ("Consume"),
         Kind => Subprogram_Entity,
         Callable_Profile_Present => True,
         others => <>);
   begin
      Procedure_Entity.Parameters.Append
        ((Name           => To_Text ("X"),
          Canonical_Name => To_Text ("x"),
          Position       => 0,
          Mode           => In_Parameter,
          Parameter_Type =>
            (Declaration_ID => To_Text ("decl:example.t#public"),
             others => <>)));
      Document.Entities.Append (Procedure_Entity);
   end;
   Document.Annotations.Append
     ((Namespace         => To_Text ("example.test"),
       Action            => To_Text ("call"),
       Target_ID         => To_Text ("decl:example.t#public"),
       Declaration_Order => 0,
       others            => <>));
   declare
      Arguments : Expression_Access_Vectors.Vector;
   begin
      Arguments.Append
        (new Expression'
           (Kind    => Integer_Literal,
            Syntax  => To_Text ("1"),
            Literal => To_Text ("1")));
      Document.Annotations (0).Arguments.Append
        ((Kind => Expression_Value,
          Expression_Data =>
            new Expression'
              (Kind                   => Function_Call,
               Syntax                 => To_Text ("Consume (1)"),
               Resolved_Subprogram_ID =>
                 To_Text
                   ("decl:example.consume[profile=0:in:x:decl:example.t#public,result=none]#public"),
               Call_Arguments         => Arguments)));
   end;
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "a procedure cannot be used as a value expression call");
   Document.Annotations.Clear;
   Document.Entities.Clear;

   Document.Annotations.Append
     ((Namespace         => To_Text ("example.test"),
       Action            => To_Text ("attribute"),
       Target_ID         => To_Text ("decl:example.t#public"),
       Declaration_Order => 0,
       others            => <>));
   declare
      Arguments : Expression_Access_Vectors.Vector;
   begin
      Arguments.Append
        (new Expression'
           (Kind    => Integer_Literal,
            Syntax  => To_Text ("1"),
            Literal => To_Text ("1")));
      Document.Annotations (0).Arguments.Append
        ((Kind => Expression_Value,
          Expression_Data =>
            new Expression'
              (Kind           => Attribute_Reference,
               Syntax         => To_Text ("T'First (1)"),
               Prefix         =>
                 new Expression'
                   (Kind                      => Declaration_Reference,
                    Syntax                    => To_Text ("T"),
                    Referenced_Declaration_ID => To_Text ("decl:example.t#public")),
               Attribute_Name => First_Attribute,
               Attribute_Arguments => Arguments)));
   end;
   Assert
     (not Has_Errors (Validate (Document, Structural)),
      "First accepts one dimension argument");
   Document.Annotations.Clear;

   Document.Context.Scenario.Append
     ((Name => To_Text ("1BAD"), Value => To_Text ("fixture")));
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "scenario names use the schema's closed lexical grammar");
   Document.Context.Scenario.Clear;

   Document.Declarations (0).Display_Name :=
     To_Text ((1 => Character'Val (16#FF#)));
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "all serialized display text must be valid UTF-8");
   Document.Declarations (0).Display_Name := To_Text ("T");

   Document.Context.Consumer_Unit := To_Text ("x%4d%69%58%65%44.generated");
   Document.Context.Derivation_Unit := To_Text ("x%41%64%61");
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "v1 accessibility context rejects extended unit identifiers");
   Document.Context.Consumer_Unit := To_Text ("flyology.generated");
   Document.Context.Derivation_Unit := To_Text ("example");

   Document.Declarations (0).Display_Name := To_Text ("");
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "retained display names must be nonempty");
   Document.Declarations (0).Display_Name := To_Text ("T");

   Document.Components.Append
     ((Stable_ID         => To_Text ("decl:example.t.value#public"),
       Owner_ID          => To_Text ("decl:example.t#public"),
       Name              => To_Text ("Value"),
       Canonical_Name    => To_Text ("value"),
       Declaration_Order => 0,
       others            => <>));
   Assert
     (Has_Code
        (Validate (Document, Structural), Anonymous_Type_Rejected),
      "anonymous component type use-sites receive the explicit diagnostic");
   Document.Components.Clear;

   --  Generic formal vocabulary and modes are closed independently of the
   --  actual-kind vocabulary.
   Document.Entities.Append
     ((Stable_ID => To_Text ("decl:example.template#public"),
       Canonical_Name => To_Text ("example.template"),
       Display_Name => To_Text ("Template"),
       Kind => Generic_Template_Entity,
       others => <>));
   Document.Entities.Append
     ((Stable_ID => To_Text ("decl:example.template.v#public"),
       Canonical_Name => To_Text ("example.template.v"),
       Display_Name => To_Text ("V"),
       Owner_ID => To_Text ("decl:example.template#public"),
       Kind => Generic_Formal_Entity,
       Formal_Kind => Value_Actual,
       others => <>));
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "value is an actual kind, not an Ada generic formal kind");
   Document.Entities.Delete_Last;
   Document.Entities.Append
     ((Stable_ID =>
         To_Text
           ("decl:example.template.o[object=out,type=decl:example.t#public]#public"),
       Canonical_Name => To_Text ("example.template.o"),
       Display_Name => To_Text ("O"),
       Owner_ID => To_Text ("decl:example.template#public"),
       Kind => Generic_Formal_Entity,
       Formal_Kind => Object_Actual,
       Entity_Type =>
         (Declaration_ID => To_Text ("decl:example.t#public"), others => <>),
       Object_Mode_Present => True,
       Object_Mode => Out_Parameter,
       others => <>));
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "generic object formals reject unsupported out mode");
   Document.Entities.Clear;

   --  Subtype/derived edges are acyclic even though record/access type graphs
   --  may legitimately be recursive.
   Document.Declarations (0).Form := Subtype_Declaration_Form;
   Document.Declarations (0).Base_Subtype.Declaration_ID :=
     To_Text ("decl:example.u#public");
   Document.Declarations (0).References.Append
     ((Role => Base_Subtype_Role,
       Target =>
         (Declaration_ID => To_Text ("decl:example.u#public"), others => <>),
       others => <>));
   Document.Declarations.Append
     ((Stable_ID => To_Text ("decl:example.u#public"),
       Canonical_Name => To_Text ("example.u"),
       Display_Name => To_Text ("U"),
       Form => Subtype_Declaration_Form,
       Kind => Signed_Integer,
       Base_Subtype =>
         (Declaration_ID => To_Text ("decl:example.t#public"), others => <>),
       Representation_Available => Known_Boolean (True),
       Consumer_Can_Name_Components => Known_Boolean (False),
       others => <>));
   Document.Declarations (1).Constraint :=
     (Kind => Scalar_Range_Constraint,
      Provenance => Declared_Subtype,
      Low =>
        new Expression'
          (Kind => Integer_Literal,
           Syntax => To_Text ("0"), Literal => To_Text ("0")),
      High =>
        new Expression'
          (Kind => Integer_Literal,
           Syntax => To_Text ("10"), Literal => To_Text ("10")),
      Staticness => Known_Boolean (True),
      Static_Low => Known_Decimal ("0"),
      Static_High => Known_Decimal ("10"),
      Predicate => Known_Boolean (False),
      others => <>);
   for Name in Fact_Name range Definite_Fact .. Contains_Controlled_Fact loop
      Document.Declarations (1).Facts.Append
        ((Name => Name,
          Fact => Known_Boolean (Name = Definite_Fact)));
   end loop;
   Document.Declarations (1).References.Append
     ((Role => Base_Subtype_Role,
       Target =>
         (Declaration_ID => To_Text ("decl:example.t#public"), others => <>),
       others => <>));
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "base-subtype cycles are rejected");
   Document.Declarations.Delete_Last;
   Document.Declarations (0).Form := Type_Declaration_Form;
   Document.Declarations (0).Base_Subtype := (others => <>);
   Document.Declarations (0).References.Clear;

   --  Array dimensions accept only an exact discrete range constraint.
   Document.Declarations.Append
     ((Stable_ID => To_Text ("decl:example.a#public"),
       Canonical_Name => To_Text ("example.a"),
       Display_Name => To_Text ("A"),
       Kind => Array_Type,
       Array_Rank => 1,
       Array_Component =>
         (Declaration_ID => To_Text ("decl:example.t#public"), others => <>),
       Representation_Available => Known_Boolean (True),
       Consumer_Can_Name_Components => Known_Boolean (False),
       others => <>));
   for Name in Fact_Name range Definite_Fact .. Contains_Controlled_Fact loop
      Document.Declarations (1).Facts.Append
        ((Name => Name,
          Fact => Known_Boolean (Name = Definite_Fact)));
   end loop;
   Document.Declarations (1).Facts.Append
     ((Name => Constrained_Fact, Fact => Known_Boolean (True)));
   Document.Declarations (1).Array_Dimensions.Append
     ((Position => 1,
       Index_Subtype =>
         (Declaration_ID => To_Text ("decl:example.t#public"), others => <>),
       Constraint =>
         (Kind => Digits_Constraint,
          Provenance => Declared_Subtype,
          Low =>
            new Expression'
              (Kind => Integer_Literal,
               Syntax => To_Text ("6"), Literal => To_Text ("6")),
          Static_Value => Known_Decimal ("6"),
          others => <>),
       others => <>));
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "array index dimensions reject non-range constraints");
   Document.Declarations.Delete_Last;

   --  A minimal exact variant passes, then wrong IDs and wrong name targets
   --  are rejected by the Ada validator itself.
   Document.Declarations.Append
     ((Stable_ID => To_Text ("decl:example.z#public"),
       Canonical_Name => To_Text ("example.z"),
       Display_Name => To_Text ("Z"),
       Kind => Record_Type,
       Representation_Available => Known_Boolean (True),
       Consumer_Can_Name_Components => Known_Boolean (True),
       others => <>));
   for Name in Fact_Name range Definite_Fact .. Contains_Controlled_Fact loop
      Document.Declarations (1).Facts.Append
        ((Name => Name,
          Fact => Known_Boolean (Name = Definite_Fact)));
   end loop;
   Document.Discriminants.Append
     ((Stable_ID => To_Text ("decl:example.z.kind#public"),
       Owner_ID => To_Text ("decl:example.z#public"),
       Name => To_Text ("Kind"),
       Canonical_Name => To_Text ("kind"),
       Discriminant_Type =>
         (Declaration_ID => To_Text ("decl:example.t#public"), others => <>),
       Aliased_Flag => Known_Boolean (False),
       Constant_Flag => Known_Boolean (True),
       others => <>));
   Document.Variants.Append
     ((Stable_ID => To_Text ("decl:example.z.variant.kind#public"),
       Owner_ID => To_Text ("decl:example.z#public"),
       Selector_Discriminant_ID => To_Text ("decl:example.z.kind#public"),
       others => <>));
   Document.Variants (0).Alternatives.Append
     ((Stable_ID => To_Text ("decl:example.z.variant.kind.alternative.0#public"),
       others => <>));
   Document.Variants (0).Alternatives (0).Choices.Append
     ((Kind => Expression_Choice,
       Syntax => To_Text ("0"),
       Expression =>
         new Expression'
           (Kind => Integer_Literal,
            Syntax => To_Text ("0"), Literal => To_Text ("0")),
       Static_Low => Known_Decimal ("0"),
       others => <>));
   Assert
     (not Has_Errors (Validate (Document, Structural)),
      "minimal exact variant graph passes structural validation");
   Document.Variants (0).Alternatives (0).Stable_ID :=
     To_Text ("decl:example.z.variant.kind.alternative.9#public");
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "variant alternative IDs encode canonical rank");
   Document.Variants (0).Alternatives (0).Stable_ID :=
     To_Text ("decl:example.z.variant.kind.alternative.0#public");
   Document.Variants (0).Alternatives (0).Choices.Clear;
   Document.Variants (0).Alternatives (0).Choices.Append
     ((Kind => Name_Choice,
       Syntax => To_Text ("T"),
       Resolved_ID => To_Text ("decl:example.t#public"),
       Static_Low => Known_Decimal ("0"),
       others => <>));
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "variant name choices cannot resolve to a type declaration");
   Document.Variants.Clear;
   Document.Discriminants.Clear;
   Document.Declarations.Delete_Last;

   Document.Enumeration_Literals.Append
     ((Stable_ID => To_Text ("decl:example.t.zero#public"),
       Owner_ID => To_Text ("decl:example.t#public"),
       Name => To_Text ("Zero"),
       Canonical_Name => To_Text ("zero"),
       Position => To_Text ("0"),
       others => <>));
   Document.Annotations.Append
     ((Namespace => To_Text ("example.test"),
       Action => To_Text ("literal"),
       Target_ID => To_Text ("decl:example.t.zero#public"),
       Expression_Syntax => To_Text ("Literal_Annotation"),
       others => <>));
   Assert
     (not Has_Code (Validate (Document, Structural), Unresolved_Reference),
      "enum literals are valid annotation targets in the Ada model");
   Document.Annotations.Clear;
   Document.Enumeration_Literals.Clear;

   Document.Declarations (0).Facts (0).Fact := Unknown_Fact;
   Assert
     (not Has_Errors (Validate (Document, Structural)),
      "structural validation preserves Unknown facts");
   Assert
     (Has_Code
        (Validate (Document, Strict_Consumer),
         Imprecise_Mandatory_Fact),
      "strict validation rejects mandatory Unknown facts");

   Document.Required_Features.Append ("future/mandatory");
   Assert
     (Has_Errors (Validate (Document, Structural)),
      "unknown required features fail closed");

   Ada.Text_IO.Put_Line ("All flyology_type_ir tests passed");
exception
   when Failure : others =>
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         Ada.Exceptions.Exception_Information (Failure));
      raise;
end Tests;
