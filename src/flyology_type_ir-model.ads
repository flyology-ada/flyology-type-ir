with Ada.Containers.Indefinite_Vectors;
with Ada.Containers.Vectors;
with Ada.Strings.Unbounded;

package Flyology_Type_IR.Model is
   pragma Preelaborate;

   package US renames Ada.Strings.Unbounded;
   subtype Text is US.Unbounded_String;

   function To_Text (Value : String) return Text renames US.To_Unbounded_String;
   function Image (Value : Text) return String renames US.To_String;

   package Text_Vectors is new Ada.Containers.Indefinite_Vectors
     (Index_Type   => Natural,
      Element_Type => String);

   type View_Kind is
     (Public_View, Private_View, Full_View, Incomplete_View, Class_Wide_View);

   type Constraint_Shape;
   type Constraint_Access is access all Constraint_Shape;

   type Type_Reference is record
      Declaration_ID : Text;
      Use_Site_Constraint : Constraint_Access;
   end record;

   type Expression_Kind is
     (Boolean_Literal,
      Character_Literal,
      Integer_Literal,
      Decimal_Literal,
      String_Literal,
      Declaration_Reference,
      Unary_Operation,
      Binary_Operation,
      Attribute_Reference,
      Type_Conversion,
      Qualified_Expression,
      Function_Call,
      Selected_Component,
      Indexed_Component,
      Unsupported_Expression);
   type Operator_Kind is
     (Plus_Operator,
      Minus_Operator,
      Multiply_Operator,
      Divide_Operator,
      Mod_Operator,
      Rem_Operator,
      Exponent_Operator,
      Abs_Operator,
      Not_Operator,
      And_Operator,
      Or_Operator,
      Xor_Operator,
      Equal_Operator,
      Not_Equal_Operator,
      Less_Operator,
      Less_Equal_Operator,
      Greater_Operator,
      Greater_Equal_Operator);
   type Attribute_Kind is
     (First_Attribute,
      Last_Attribute,
      Length_Attribute,
      Pos_Attribute,
      Val_Attribute,
      Succ_Attribute,
      Pred_Attribute);

   type Expression (Kind : Expression_Kind := Integer_Literal);
   type Expression_Access is access constant Expression;
   package Expression_Access_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Expression_Access);
   type Expression (Kind : Expression_Kind := Integer_Literal) is record
      Syntax : Text;
      case Kind is
         when Character_Literal =>
            Character_Data             : Text;
            Resolved_Character_Type_ID : Text;
         when Integer_Literal | String_Literal =>
            Literal : Text;
         when Boolean_Literal =>
            Boolean_Data : Boolean := False;
         when Decimal_Literal =>
            Numerator   : Text;
            Denominator : Text;
         when Declaration_Reference =>
            Referenced_Declaration_ID : Text;
         when Unary_Operation =>
            Unary_Operator          : Operator_Kind := Plus_Operator;
            Operand                 : Expression_Access;
            Unary_Operator_Is_Predefined : Boolean := False;
            Operand_Type_ID              : Text;
            Unary_Result_Type_ID         : Text;
         when Binary_Operation =>
            Binary_Operator         : Operator_Kind := Plus_Operator;
            Left                    : Expression_Access;
            Right                   : Expression_Access;
            Binary_Operator_Is_Predefined : Boolean := False;
            Left_Type_ID                  : Text;
            Right_Type_ID                 : Text;
            Binary_Result_Type_ID         : Text;
         when Attribute_Reference =>
            Prefix         : Expression_Access;
            Attribute_Name : Attribute_Kind := First_Attribute;
            Attribute_Arguments : Expression_Access_Vectors.Vector;
         when Type_Conversion | Qualified_Expression =>
            Target_Subtype    : Type_Reference;
            Converted_Operand : Expression_Access;
         when Function_Call =>
            Resolved_Subprogram_ID : Text;
            Call_Arguments         : Expression_Access_Vectors.Vector;
         when Selected_Component =>
            Selected_Prefix : Expression_Access;
            Selector_ID     : Text;
         when Indexed_Component =>
            Indexed_Prefix : Expression_Access;
            Index_Expressions : Expression_Access_Vectors.Vector;
         when Unsupported_Expression =>
            Unsupported_Feature_Code : Text;
      end case;
   end record;

   type Value_Kind is
     (Boolean_Value,
      Decimal_Integer_Value,
      Exact_Rational_Value,
      Text_Value,
      Expression_Value);
   type Typed_Value (Kind : Value_Kind := Text_Value) is record
      case Kind is
         when Boolean_Value =>
            Boolean_Data : Boolean := False;
         when Decimal_Integer_Value =>
            Decimal_Data : Text;
         when Exact_Rational_Value =>
            Numerator_Data   : Text;
            Denominator_Data : Text;
         when Text_Value =>
            Text_Data : Text;
         when Expression_Value =>
            Expression_Data : Expression_Access;
      end case;
   end record;

   package Typed_Value_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Typed_Value);

   type Fact_Status is (Known, Unknown, Unsupported);
   type Fact_Name is
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
      Aliased_Fact,
      Constant_Fact,
      Predicate_Fact,
      Constraint_Staticness_Fact,
      Modulus_Fact,
      Digits_Fact,
      Delta_Fact,
      Small_Fact,
      Constrained_Fact,
      Null_Exclusion_Fact);

   function Fact_Key (Name : Fact_Name) return String;

   --  Known carries an exact semantic value. Unknown means the extractor could
   --  not establish the answer in its exact analysis context. Unsupported means
   --  the construct was understood but is outside this IR version or profile.
   --  Code is empty for Known, a stable reason code for Unknown, and a stable
   --  feature code for Unsupported. Detail is diagnostic and non-semantic.
   type Semantic_Fact is record
      Status : Fact_Status := Unknown;
      Value  : Typed_Value;
      Code   : Text;
      Detail : Text;
   end record;

   function Is_Compatible
     (Name : Fact_Name;
      Fact : Semantic_Fact) return Boolean;

   type Fact_Entry is record
      Name      : Fact_Name := Definite_Fact;
      Fact      : Semantic_Fact;
   end record;

   package Fact_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Fact_Entry);

   type Type_Kind is
     (Signed_Integer,
      Modular_Integer,
      Enumeration,
      Floating_Point,
      Ordinary_Fixed_Point,
      Decimal_Fixed_Point,
      Boolean_Type,
      Character_Type,
      Array_Type,
      Record_Type,
      Access_Type,
      Interface_Type,
      Task_Type,
      Protected_Type,
      Private_Type,
      Incomplete_Type,
      Class_Wide_Type);

   type Reference_Role is
     (Base_Subtype_Role,
      Parent_Type_Role);

   type Declaration_Form is
     (Type_Declaration_Form,
      Subtype_Declaration_Form,
      Derived_Declaration_Form,
      Private_Declaration_Form,
      Incomplete_Declaration_Form,
      Class_Wide_Declaration_Form);

   type Named_Reference is record
      Role   : Reference_Role := Parent_Type_Role;
      Label  : Text;
      Target : Type_Reference;
   end record;

   package Reference_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Named_Reference);

   type Constraint_Provenance is
     (No_Constraint, Declared_Subtype, Inherited_From_Base, Use_Site);
   type Constraint_Kind is
     (Unconstrained,
      Scalar_Range_Constraint,
      Array_Index_Constraint,
      Discriminant_Constraint,
      Digits_Constraint,
      Delta_Constraint);
   type Array_Dimension;
   type Array_Dimension_Access is access all Array_Dimension;
   type Discriminant_Association;
   type Discriminant_Association_Access is access all Discriminant_Association;
   type Constraint_Shape is record
      Kind       : Constraint_Kind := Unconstrained;
      Provenance : Constraint_Provenance := No_Constraint;
      Low        : Expression_Access;
      High       : Expression_Access;
      Staticness : Semantic_Fact;
      Static_Low  : Semantic_Fact;
      Static_High : Semantic_Fact;
      Static_Value : Semantic_Fact;
      Secondary_Value : Semantic_Fact;
      Predicate  : Semantic_Fact;
      First_Dimension   : Array_Dimension_Access;
      First_Association : Discriminant_Association_Access;
   end record;

   type Array_Dimension is record
      Position      : Positive := 1;
      Index_Subtype : Type_Reference;
      Constraint    : Constraint_Shape;
      Next          : Array_Dimension_Access;
   end record;

   type Discriminant_Association is record
      Discriminant_ID : Text;
      Expression      : Expression_Access;
      Staticness      : Semantic_Fact;
      Static_Value_Present : Boolean := False;
      Static_Value    : Semantic_Fact;
      Next            : Discriminant_Association_Access;
   end record;

   package Dimension_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Array_Dimension);

   type Source_Location is record
      Unit_Name : Text;
      File      : Text;
      Line      : Natural := 0;
      Column    : Natural := 0;
   end record;

   type Type_Declaration is record
      Stable_ID         : Text;
      Canonical_Name    : Text;
      Display_Name      : Text;
      Form              : Declaration_Form := Type_Declaration_Form;
      View              : View_Kind := Public_View;
      Kind              : Type_Kind := Private_Type;
      Declaration_Order : Natural := 0;
      Related_View_IDs  : Text_Vectors.Vector;
      Representation_Available : Semantic_Fact;
      Consumer_Can_Name_Components : Semantic_Fact;
      Location          : Source_Location;
      Facts             : Fact_Vectors.Vector;
      References        : Reference_Vectors.Vector;
      Base_Subtype      : Type_Reference;
      Constraint        : Constraint_Shape;
      Digits_Constraint : Constraint_Shape;
      Delta_Constraint  : Constraint_Shape;
      Array_Rank        : Natural := 0;
      Array_Dimensions  : Dimension_Vectors.Vector;
      Array_Component   : Type_Reference;
      Designated_Subtype : Type_Reference;
      Enum_Literal_IDs  : Text_Vectors.Vector;
   end record;

   package Declaration_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Type_Declaration);

   type Component_Declaration is record
      Stable_ID         : Text;
      Owner_ID          : Text;
      Name              : Text;
      Canonical_Name    : Text;
      Declaration_Order : Natural := 0;
      Component_Type    : Type_Reference;
      Variant_Path      : Text_Vectors.Vector;
      Facts             : Fact_Vectors.Vector;
      Default_Syntax    : Text;
      Default_Present   : Boolean := False;
      Default_Expression : Expression_Access;
      Default_Staticness : Semantic_Fact;
      Default_Static_Value_Present : Boolean := False;
      Default_Value     : Semantic_Fact;
   end record;

   package Component_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Component_Declaration);

   type Discriminant_Declaration is record
      Stable_ID         : Text;
      Owner_ID          : Text;
      Name              : Text;
      Canonical_Name    : Text;
      Declaration_Order : Natural := 0;
      Discriminant_Type : Type_Reference;
      Aliased_Flag       : Semantic_Fact;
      Constant_Flag      : Semantic_Fact;
      Default_Syntax    : Text;
      Default_Present   : Boolean := False;
      Default_Expression : Expression_Access;
      Default_Staticness : Semantic_Fact;
      Default_Static_Value_Present : Boolean := False;
      Default_Value     : Semantic_Fact;
   end record;

   package Discriminant_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Discriminant_Declaration);

   type Enumeration_Literal is record
      Stable_ID         : Text;
      Owner_ID          : Text;
      Name              : Text;
      Canonical_Name    : Text;
      Declaration_Order : Natural := 0;
      Position          : Text;
   end record;

   package Enumeration_Literal_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Enumeration_Literal);

   type Choice_Kind is
     (Expression_Choice, Name_Choice, Range_Choice, Subtype_Choice, Others_Choice);

   type Discrete_Choice is record
      Kind        : Choice_Kind := Expression_Choice;
      Syntax      : Text;
      Resolved_ID : Text;
      Resolved_Ref : Type_Reference;
      Expression  : Expression_Access;
      Low         : Expression_Access;
      High        : Expression_Access;
      Static_Low  : Semantic_Fact;
      Static_High : Semantic_Fact;
   end record;

   package Choice_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Discrete_Choice);

   type Variant_Alternative is record
      Stable_ID         : Text;
      Declaration_Order : Natural := 0;
      Choices           : Choice_Vectors.Vector;
      Component_IDs     : Text_Vectors.Vector;
      Nested_Variant_ID : Text;
   end record;

   package Alternative_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Variant_Alternative);

   --  Variant parts form an explicit graph. Alternatives retain exact choices,
   --  including others, and nested parts are referenced rather than flattened.
   type Variant_Part is record
      Stable_ID              : Text;
      Owner_ID               : Text;
      Parent_Alternative_ID  : Text;
      Selector_Discriminant_ID : Text;
      Alternatives           : Alternative_Vectors.Vector;
   end record;

   package Variant_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Variant_Part);

   type Generic_Actual_Kind is
     (Type_Actual, Value_Actual, Object_Actual, Package_Actual, Subprogram_Actual);
   type Generic_Actual_Origin is
     (Positional_Actual, Named_Actual, Default_Actual);
   type Generic_Actual is record
      Stable_ID         : Text;
      Instance_ID       : Text;
      Template_ID       : Text;
      Formal_ID         : Text;
      Formal_Name       : Text;
      Formal_Canonical_Name : Text;
      Declaration_Order : Natural := 0;
      Kind              : Generic_Actual_Kind := Type_Actual;
      Origin            : Generic_Actual_Origin := Positional_Actual;
      Type_Value        : Type_Reference;
      Semantic_Value    : Semantic_Fact;
      Declaration_Value : Text;
   end record;

   package Generic_Actual_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Generic_Actual);

   type Entity_Kind is
     (Object_Entity,
      Package_Entity,
      Subprogram_Entity,
      Generic_Formal_Entity,
      Generic_Template_Entity);
   type Parameter_Mode is
     (In_Parameter, Out_Parameter, In_Out_Parameter);
   type Formal_Type_Contract is (Signed_Integer_Range_Contract);
   type Formal_Package_Contract is (Box_Only_Contract);
   type Callable_Parameter is record
      Name           : Text;
      Canonical_Name : Text;
      Position       : Natural := 0;
      Mode           : Parameter_Mode := In_Parameter;
      Parameter_Type : Type_Reference;
   end record;
   package Callable_Parameter_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Callable_Parameter);
   type Semantic_Entity is record
      Stable_ID         : Text;
      Canonical_Name    : Text;
      Owner_ID          : Text;
      Instantiated_Template_ID : Text;
      Declaration_Order : Natural := 0;
      Kind              : Entity_Kind := Object_Entity;
      Display_Name      : Text;
      Formal_Kind       : Generic_Actual_Kind := Type_Actual;
      Formal_Template_ID : Text;
      Formal_Package_Contract_Present : Boolean := False;
      Package_Contract   : Formal_Package_Contract := Box_Only_Contract;
      Formal_Type_Contract_Present : Boolean := False;
      Type_Contract      : Formal_Type_Contract := Signed_Integer_Range_Contract;
      Entity_Type       : Type_Reference;
      Callable_Profile_Present : Boolean := False;
      Parameters        : Callable_Parameter_Vectors.Vector;
      Result_Present    : Boolean := False;
      Result_Type       : Type_Reference;
      Object_Mode_Present : Boolean := False;
      Object_Mode         : Parameter_Mode := In_Parameter;
   end record;

   package Entity_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Semantic_Entity);

   type Annotation is record
      Namespace         : Text;
      Action            : Text;
      Target_ID         : Text;
      Declaration_Order : Natural := 0;
      Inherited         : Boolean := False;
      Arguments         : Typed_Value_Vectors.Vector;
      Expression_Syntax : Text;
   end record;

   package Annotation_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Annotation);

   type Extension is record
      Namespace      : Text;
      Canonical_JSON : Text;
   end record;

   package Extension_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Extension);

   type Source_Digest is record
      Logical_Name   : Text;
      Content_Digest : Text;
   end record;

   package Source_Digest_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Source_Digest);

   type Selected_Source is record
      Unit_Name      : Text;
      Logical_Name   : Text;
      Source_Kind    : Text;
      Content_Digest : Text;
   end record;
   package Selected_Source_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Selected_Source);

   type Scenario_Binding is record
      Name  : Text;
      Value : Text;
   end record;

   package Scenario_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Scenario_Binding);

   type Extractor_Context_Kind is (Extraction_Context, Fixture_Context);

   type Extractor_Context is record
      Kind               : Extractor_Context_Kind := Extraction_Context;
      Extractor_Version  : Text;
      Libadalang_Version : Text;
      GNAT_Version       : Text;
      Compiler_Path      : Text;
      Compiler_Identity  : Text;
      Canonical_GPR_Path : Text;
      Legality_Arguments : Text_Vectors.Vector;
      Legality_Environment : Scenario_Vectors.Vector;
      Legality_Tool_Identity : Text;
      Legality_Working_Directory : Text;
      Legality_Command_Fingerprint : Text;
      Legality_Succeeded : Boolean := False;
      Effective_Closure_Digest : Text;
      Compiler_Switches  : Text_Vectors.Vector;
      Configuration_Pragmas : Source_Digest_Vectors.Vector;
      Project_Files          : Source_Digest_Vectors.Vector;
      Runtime_Sources    : Source_Digest_Vectors.Vector;
      Selected_Units     : Selected_Source_Vectors.Vector;
      Consumer_Unit      : Text;
      Derivation_Unit    : Text;
      Accessibility_Region : Text;
      Project_Name       : Text;
      Project_Closure    : Text_Vectors.Vector;
      Requested_Units    : Text_Vectors.Vector;
      Scenario           : Scenario_Vectors.Vector;
      Target             : Text;
      Runtime            : Text;
   end record;

   type IR_Document is record
      IR_Version        : Positive := Current_IR_Version;
      Required_Features : Text_Vectors.Vector;
      Optional_Features : Text_Vectors.Vector;
      Declarations      : Declaration_Vectors.Vector;
      Components        : Component_Vectors.Vector;
      Discriminants     : Discriminant_Vectors.Vector;
      Entities          : Entity_Vectors.Vector;
      Enumeration_Literals : Enumeration_Literal_Vectors.Vector;
      Generic_Actuals   : Generic_Actual_Vectors.Vector;
      Annotations       : Annotation_Vectors.Vector;
      Variants          : Variant_Vectors.Vector;
      Extensions        : Extension_Vectors.Vector;
      Context           : Extractor_Context;
   end record;

   function Is_Canonical_Decimal (Value : String) return Boolean;
   function Is_Valid_UTF8 (Value : String) return Boolean;
   function Is_Canonical_Name (Value : String) return Boolean;
   function Is_Canonical_Semantic_ID (Value : String) return Boolean;
   function Is_Well_Formed (Fact : Semantic_Fact) return Boolean;
end Flyology_Type_IR.Model;
