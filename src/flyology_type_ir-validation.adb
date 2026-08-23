with Ada.Characters.Handling;
with Ada.Containers;
package body Flyology_Type_IR.Validation is
   use type Ada.Containers.Count_Type;
   use type Model.Fact_Status;
   use type Model.Fact_Name;
   use type Model.Expression_Access;
   use type Model.Constraint_Access;
   use type Model.Type_Kind;
   use type Model.Declaration_Form;
   use type Model.View_Kind;
   use type Model.Array_Dimension_Access;
   use type Model.Discriminant_Association_Access;
   use type Model.Constraint_Kind;
   use type Model.Constraint_Provenance;
   use type Model.Choice_Kind;
   use type Model.Entity_Kind;
   use type Model.Value_Kind;
   use type Model.Generic_Actual_Kind;
   use type Model.Operator_Kind;
   use type Model.Reference_Role;
   use type Model.Attribute_Kind;
   use type Model.Parameter_Mode;
   use type Model.Extractor_Context_Kind;

   function Overlay_Replacement_Allowed
     (Original  : Model.Semantic_Fact;
      Candidate : Model.Semantic_Fact) return Boolean
   is
      pragma Unreferenced (Original, Candidate);
   begin
      return False;
   end Overlay_Replacement_Allowed;

   function Has_Errors (Diagnostics : Diagnostic_Vectors.Vector) return Boolean is
   begin
      for Item of Diagnostics loop
         if Item.Level = Error then
            return True;
         end if;
      end loop;
      return False;
   end Has_Errors;

   function Validate
     (Document : Model.IR_Document;
      Profile  : Validation_Profile)
      return Diagnostic_Vectors.Vector
   is
      Result : Diagnostic_Vectors.Vector;

      package Constraint_Access_Vectors is new Ada.Containers.Vectors
        (Index_Type   => Natural,
         Element_Type => Model.Constraint_Access);
      package Dimension_Access_Vectors is new Ada.Containers.Vectors
        (Index_Type   => Natural,
         Element_Type => Model.Array_Dimension_Access);
      package Association_Access_Vectors is new Ada.Containers.Vectors
        (Index_Type   => Natural,
         Element_Type => Model.Discriminant_Association_Access);
      Expression_Stack : Model.Expression_Access_Vectors.Vector;
      Constraint_Stack : Constraint_Access_Vectors.Vector;
      Key_Expression_Stack : Model.Expression_Access_Vectors.Vector;
      Key_Constraint_Stack : Constraint_Access_Vectors.Vector;

      procedure Add
        (Code    : Diagnostic_Code;
         Path    : String;
         Message : String)
      is
      begin
         Result.Append
           (Diagnostic'(Level   => Error,
             Code    => Code,
             Path    => Model.To_Text (Path),
             Message => Model.To_Text (Message)));
      end Add;

      procedure Check_UTF8 (Value : String; Path : String) is
      begin
         if not Model.Is_Valid_UTF8 (Value) then
            Add (Invalid_Fact, Path, "serialized text is not valid UTF-8");
         end if;
      end Check_UTF8;

      procedure Check_UTF8 (Value : Model.Text; Path : String) is
      begin
         Check_UTF8 (Model.Image (Value), Path);
      end Check_UTF8;

      function Declaration_Exists (ID : String) return Boolean is
      begin
         for Item of Document.Declarations loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         return False;
      end Declaration_Exists;

      function Root_Type_ID
        (ID : String; Depth : Natural := 0) return String
      is
      begin
         if Depth > Natural (Document.Declarations.Length) then
            return "";
         end if;
         for Item of Document.Declarations loop
            if Model.Image (Item.Stable_ID) = ID then
               if Item.Form = Model.Subtype_Declaration_Form
                 and then Model.US.Length (Item.Base_Subtype.Declaration_ID) > 0
               then
                  return Root_Type_ID
                    (Model.Image (Item.Base_Subtype.Declaration_ID), Depth + 1);
               end if;
               return ID;
            end if;
         end loop;
         return "";
      end Root_Type_ID;

      function Type_Family_Key (ID : String) return String is
         Root : constant String := Root_Type_ID (ID);
      begin
         if Root'Length > 11
           and then Root (Root'Last - 10 .. Root'Last) = "#class_wide"
         then
            return Root;
         elsif Root'Length > 11
           and then Root (Root'Last - 10 .. Root'Last) = "#incomplete"
         then
            return Root (Root'First .. Root'Last - 11);
         elsif Root'Length > 8
           and then Root (Root'Last - 7 .. Root'Last) = "#private"
         then
            return Root (Root'First .. Root'Last - 8);
         elsif Root'Length > 7
           and then Root (Root'Last - 6 .. Root'Last) = "#public"
         then
            return Root (Root'First .. Root'Last - 7);
         elsif Root'Length > 5
           and then Root (Root'Last - 4 .. Root'Last) = "#full"
         then
            return Root (Root'First .. Root'Last - 5);
         end if;
         return "";
      end Type_Family_Key;

      function Base_Path_Acyclic
        (Start_ID   : String;
         Current_ID : String;
         Depth      : Natural := 0) return Boolean
      is
      begin
         if Depth > Natural (Document.Declarations.Length) then
            return False;
         end if;
         for Item of Document.Declarations loop
            if Model.Image (Item.Stable_ID) = Current_ID
              and then Item.Form in Model.Subtype_Declaration_Form
                | Model.Derived_Declaration_Form
            then
               if Model.Image (Item.Base_Subtype.Declaration_ID) = Start_ID then
                  return False;
               end if;
               return Base_Path_Acyclic
                 (Start_ID,
                  Model.Image (Item.Base_Subtype.Declaration_ID),
                  Depth + 1);
            end if;
         end loop;
         return True;
      end Base_Path_Acyclic;

      function Declaration_Family_Key (ID : String) return String is
      begin
         if ID'Length > 11
           and then ID (ID'Last - 10 .. ID'Last) = "#class_wide"
         then
            return ID (ID'First .. ID'Last - 11);
         elsif ID'Length > 11
           and then ID (ID'Last - 10 .. ID'Last) = "#incomplete"
         then
            return ID (ID'First .. ID'Last - 11);
         elsif ID'Length > 8
           and then ID (ID'Last - 7 .. ID'Last) = "#private"
         then
            return ID (ID'First .. ID'Last - 8);
         elsif ID'Length > 7
           and then ID (ID'Last - 6 .. ID'Last) = "#public"
         then
            return ID (ID'First .. ID'Last - 7);
         elsif ID'Length > 5
           and then ID (ID'Last - 4 .. ID'Last) = "#full"
         then
            return ID (ID'First .. ID'Last - 5);
         end if;
         return "";
      end Declaration_Family_Key;

      function Declaration_Is_Discrete (ID : String) return Boolean is
      begin
         for Item of Document.Declarations loop
            if Model.Image (Item.Stable_ID) = ID then
               return Item.Kind in Model.Signed_Integer
                 | Model.Modular_Integer | Model.Enumeration
                 | Model.Boolean_Type | Model.Character_Type;
            end if;
         end loop;
         return False;
      end Declaration_Is_Discrete;

      function Component_Exists (ID : String) return Boolean is
      begin
         for Item of Document.Components loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         return False;
      end Component_Exists;

      function Discriminant_Exists (ID : String) return Boolean is
      begin
         for Item of Document.Discriminants loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         return False;
      end Discriminant_Exists;

      function Enumeration_Literal_Exists (ID : String) return Boolean is
      begin
         for Item of Document.Enumeration_Literals loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         return False;
      end Enumeration_Literal_Exists;

      function Entity_Has_Kind
        (ID   : String;
         Kind : Model.Entity_Kind) return Boolean
      is
      begin
         for Item of Document.Entities loop
            if Model.Image (Item.Stable_ID) = ID and then Item.Kind = Kind then
               return True;
            end if;
         end loop;
         return False;
      end Entity_Has_Kind;

      function Entity_Is_Function (ID : String) return Boolean is
      begin
         for Item of Document.Entities loop
            if Model.Image (Item.Stable_ID) = ID then
               return Item.Kind = Model.Subprogram_Entity
                 and then Item.Callable_Profile_Present
                 and then Item.Result_Present;
            end if;
         end loop;
         return False;
      end Entity_Is_Function;

      function Entity_Canonical_Name (ID : String) return String is
      begin
         for Item of Document.Entities loop
            if Model.Image (Item.Stable_ID) = ID then
               return Model.Image (Item.Canonical_Name);
            end if;
         end loop;
         return "";
      end Entity_Canonical_Name;

      function Is_Name_Child (Child, Parent : String) return Boolean is
      begin
         return Parent'Length > 0
           and then Child'Length > Parent'Length
           and then Child (Child'First .. Child'First + Parent'Length - 1) = Parent
           and then Child (Child'First + Parent'Length) = '.';
      end Is_Name_Child;

      function Is_Canonical_Segment (Value : String) return Boolean is
      begin
         if not Model.Is_Canonical_Name (Value) then
            return False;
         end if;
         for Character of Value loop
            if Character = '.' then
               return False;
            end if;
         end loop;
         return True;
      end Is_Canonical_Segment;

      function Is_Scenario_Name (Value : String) return Boolean is
      begin
         if Value'Length = 0
           or else Value (Value'First) not in 'A' .. 'Z' | 'a' .. 'z'
         then
            return False;
         end if;
         for Character of Value loop
            if Character not in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9'
              and then Character /= '_'
            then
               return False;
            end if;
         end loop;
         return True;
      end Is_Scenario_Name;

      function Is_Annotation_Namespace (Value : String) return Boolean is
      begin
         if Value'Length = 0
           or else Value (Value'First) not in 'a' .. 'z' | '0' .. '9'
           or else Value (Value'Last) not in 'a' .. 'z' | '0' .. '9'
         then
            return False;
         end if;
         for Index in Value'Range loop
            declare
               Character : constant Standard.Character := Value (Index);
            begin
               if Character not in 'a' .. 'z' | '0' .. '9'
                 and then Character not in '.' | '-'
               then
                  return False;
               elsif Character = '.'
                 and then (Index = Value'First
                           or else Value (Index - 1) in '.' | '-')
               then
                  return False;
               elsif Character = '-'
                 and then (Index = Value'First
                           or else Value (Index - 1) = '.')
               then
                  return False;
               end if;
            end;
         end loop;
         return True;
      end Is_Annotation_Namespace;

      function Is_Annotation_Action (Value : String) return Boolean is
      begin
         return Value'Length > 0
           and then Value (Value'First) in 'a' .. 'z'
           and then
             (for all Character of Value =>
                Character in 'a' .. 'z' | '0' .. '9'
                or else Character in '.' | '_' | '-');
      end Is_Annotation_Action;

      function Variant_Exists (ID : String) return Boolean is
      begin
         for Item of Document.Variants loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         return False;
      end Variant_Exists;

      function Any_ID_Exists (ID : String) return Boolean is
      begin
         if Declaration_Exists (ID)
           or else Component_Exists (ID)
           or else Discriminant_Exists (ID)
           or else Variant_Exists (ID)
         then
            return True;
         end if;
         for Item of Document.Entities loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         for Item of Document.Enumeration_Literals loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         for Item of Document.Generic_Actuals loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         for Part of Document.Variants loop
            for Alternative of Part.Alternatives loop
               if Model.Image (Alternative.Stable_ID) = ID then
                  return True;
               end if;
            end loop;
         end loop;
         return False;
      end Any_ID_Exists;

      function Expression_ID_Exists (ID : String) return Boolean is
      begin
         if Declaration_Exists (ID)
           or else Component_Exists (ID)
           or else Discriminant_Exists (ID)
         then
            return True;
         end if;
         for Item of Document.Entities loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         for Item of Document.Enumeration_Literals loop
            if Model.Image (Item.Stable_ID) = ID then
               return True;
            end if;
         end loop;
         return False;
      end Expression_ID_Exists;

      function Known_Required_Feature (Name : String) return Boolean is
      begin
         return Name = "ada-type-ir/core"
           or else Name = "ada-type-ir/decimal-strings"
           or else Name = "ada-type-ir/exact-variants"
           or else Name = "ada-type-ir/graph-refs"
           or else Name = "ada-type-ir/typed-shapes";
      end Known_Required_Feature;

      function Declaration_Name_From_ID (ID : String) return String is
         Result        : Model.Text;
         Binding_Depth : Natural := 0;
      begin
         if ID'Length <= 5 then
            return "";
         end if;
         for Position in ID'First + 5 .. ID'Last loop
            case ID (Position) is
               when '[' =>
                  Binding_Depth := Binding_Depth + 1;
               when ']' =>
                  if Binding_Depth = 0 then
                     return "";
                  end if;
                  Binding_Depth := Binding_Depth - 1;
               when '#' =>
                  if Binding_Depth = 0 then
                     exit;
                  end if;
               when others =>
                  if Binding_Depth = 0 then
                     Model.US.Append (Result, ID (Position));
                  end if;
            end case;
         end loop;
         if Binding_Depth /= 0 then
            return "";
         end if;
         return Model.Image (Result);
      end Declaration_Name_From_ID;

      function Is_SHA256 (Value : String) return Boolean is
      begin
         if Value'Length /= 64 then
            return False;
         end if;
         for Character of Value loop
            if Character not in '0' .. '9'
              and then Character not in 'a' .. 'f'
            then
               return False;
            end if;
         end loop;
         return True;
      end Is_SHA256;

      function Is_Sorted_Unique
        (Values : Model.Text_Vectors.Vector) return Boolean
      is
      begin
         if Values.Length < 2 then
            return True;
         end if;
         for Index in Values.First_Index .. Values.Last_Index - 1 loop
            if Values (Index) >= Values (Index + 1) then
               return False;
            end if;
         end loop;
         return True;
      end Is_Sorted_Unique;

      function Is_Sorted_Unique
        (Values : Model.Source_Digest_Vectors.Vector) return Boolean
      is
      begin
         if Values.Length < 2 then
            return True;
         end if;
         for Index in Values.First_Index .. Values.Last_Index - 1 loop
            if Model.Image (Values (Index).Logical_Name)
              >= Model.Image (Values (Index + 1).Logical_Name)
            then
               return False;
            end if;
         end loop;
         return True;
      end Is_Sorted_Unique;

      function Is_Sorted_Unique
        (Values : Model.Selected_Source_Vectors.Vector) return Boolean
      is
         function Key (Item : Model.Selected_Source) return String is
           (Model.Image (Item.Unit_Name) & Character'Val (0)
            & Model.Image (Item.Source_Kind) & Character'Val (0)
            & Model.Image (Item.Logical_Name));
      begin
         if Values.Length < 2 then
            return True;
         end if;
         for Index in Values.First_Index .. Values.Last_Index - 1 loop
            if Key (Values (Index)) >= Key (Values (Index + 1)) then
               return False;
            end if;
         end loop;
         return True;
      end Is_Sorted_Unique;

      procedure Check_ID (ID, Path : String) is
         Seen : Natural := 0;
      begin
         if ID'Length = 0 then
            Add (Anonymous_Type_Rejected, Path, "anonymous declarations have no stable semantic identity");
            return;
         elsif not Model.Is_Canonical_Semantic_ID (ID) then
            Add (Invalid_Semantic_ID, Path, "semantic IDs must be lowercase decl: keys independent of source locations");
         end if;

         for Item of Document.Declarations loop
            if Model.Image (Item.Stable_ID) = ID then
               Seen := Seen + 1;
            end if;
         end loop;
         for Item of Document.Components loop
            if Model.Image (Item.Stable_ID) = ID then
               Seen := Seen + 1;
            end if;
         end loop;
         for Item of Document.Discriminants loop
            if Model.Image (Item.Stable_ID) = ID then
               Seen := Seen + 1;
            end if;
         end loop;
         for Item of Document.Variants loop
            if Model.Image (Item.Stable_ID) = ID then
               Seen := Seen + 1;
            end if;
            for Alternative of Item.Alternatives loop
               if Model.Image (Alternative.Stable_ID) = ID then
                  Seen := Seen + 1;
               end if;
            end loop;
         end loop;
         for Item of Document.Entities loop
            if Model.Image (Item.Stable_ID) = ID then
               Seen := Seen + 1;
            end if;
         end loop;
         for Item of Document.Enumeration_Literals loop
            if Model.Image (Item.Stable_ID) = ID then
               Seen := Seen + 1;
            end if;
         end loop;
         for Item of Document.Generic_Actuals loop
            if Model.Image (Item.Stable_ID) = ID then
               Seen := Seen + 1;
            end if;
         end loop;
         if Seen > 1 then
            Add (Duplicate_Semantic_ID, Path, "semantic IDs must be globally unique");
         end if;
      end Check_ID;

      procedure Check_Facts
        (Facts : Model.Fact_Vectors.Vector;
         Path  : String)
      is
      begin
         for Index in Facts.First_Index .. Facts.Last_Index loop
            declare
               Item      : constant Model.Fact_Entry := Facts (Index);
               Item_Path : constant String :=
                 Path & "/facts/" & Model.Fact_Key (Item.Name);
            begin
               if not Model.Is_Compatible (Item.Name, Item.Fact) then
                  Add (Invalid_Fact, Item_Path, "fact status, value kind, or reason code is invalid for this core fact");
               end if;
            end;
         end loop;

         for Left_Index in Facts.First_Index .. Facts.Last_Index loop
            for Right_Index in Left_Index + 1 .. Facts.Last_Index loop
               if Facts (Left_Index).Name = Facts (Right_Index).Name then
                  Add
                    (Invalid_Fact,
                     Path & "/facts/" & Model.Fact_Key (Facts (Left_Index).Name),
                     "core facts may occur at most once");
               end if;
            end loop;
         end loop;
      end Check_Facts;

      function Has_Known_Fact
        (Facts : Model.Fact_Vectors.Vector;
         Name  : Model.Fact_Name) return Boolean
      is
      begin
         for Item of Facts loop
            if Item.Name = Name then
               return Item.Fact.Status = Model.Known
                 and then Model.Is_Well_Formed (Item.Fact);
            end if;
         end loop;
         return False;
      end Has_Known_Fact;

      function Has_Compatible_Fact
        (Facts : Model.Fact_Vectors.Vector;
         Name  : Model.Fact_Name) return Boolean
      is
      begin
         for Item of Facts loop
            if Item.Name = Name then
               return Model.Is_Compatible (Name, Item.Fact);
            end if;
         end loop;
         return False;
      end Has_Compatible_Fact;

      function Known_Boolean_Equals
        (Facts : Model.Fact_Vectors.Vector;
         Name  : Model.Fact_Name;
         Value : Boolean) return Boolean
      is
      begin
         for Item of Facts loop
            if Item.Name = Name then
               return Item.Fact.Status = Model.Known
                 and then Model.Is_Compatible (Name, Item.Fact)
                 and then Item.Fact.Value.Boolean_Data = Value;
            end if;
         end loop;
         return False;
      end Known_Boolean_Equals;

      function Is_Positive_Decimal (Value : Model.Text) return Boolean is
         Image : constant String := Model.Image (Value);
      begin
         return Model.Is_Canonical_Decimal (Image)
           and then Image /= "0"
           and then Image (Image'First) /= '-';
      end Is_Positive_Decimal;

      function Known_Fact_Is_Positive
        (Facts : Model.Fact_Vectors.Vector;
         Name  : Model.Fact_Name) return Boolean
      is
      begin
         for Item of Facts loop
            if Item.Name = Name then
               if Item.Fact.Status /= Model.Known then
                  return True;
               elsif Item.Fact.Value.Kind = Model.Decimal_Integer_Value then
                  return Is_Positive_Decimal (Item.Fact.Value.Decimal_Data);
               elsif Item.Fact.Value.Kind = Model.Exact_Rational_Value then
                  return Is_Positive_Decimal
                    (Item.Fact.Value.Numerator_Data);
               end if;
               return False;
            end if;
         end loop;
         return True;
      end Known_Fact_Is_Positive;

      function Known_Decimal_Value
        (Facts : Model.Fact_Vectors.Vector;
         Name  : Model.Fact_Name) return String
      is
      begin
         for Item of Facts loop
            if Item.Name = Name
              and then Item.Fact.Status = Model.Known
              and then Item.Fact.Value.Kind = Model.Decimal_Integer_Value
            then
               return Model.Image (Item.Fact.Value.Decimal_Data);
            end if;
         end loop;
         return "";
      end Known_Decimal_Value;

      function Decimal_Predecessor (Value : String) return String is
         Result : String := Value;
         Cursor : Natural := Result'Last;
      begin
         if not Model.Is_Canonical_Decimal (Value)
           or else Value = "0" or else Value (Value'First) = '-'
         then
            return "";
         end if;
         while Result (Cursor) = '0' loop
            Result (Cursor) := '9';
            Cursor := Cursor - 1;
         end loop;
         Result (Cursor) :=
           Character'Val (Character'Pos (Result (Cursor)) - 1);
         if Result'Length > 1 and then Result (Result'First) = '0' then
            return Result (Result'First + 1 .. Result'Last);
         end if;
         return Result;
      end Decimal_Predecessor;

      procedure Check_Contained_Risk
        (Owner : Model.Type_Declaration;
         Child : Model.Type_Reference;
         Path  : String)
      is
         Unconstrained_Ref : constant Boolean :=
           Child.Use_Site_Constraint = null
           or else Child.Use_Site_Constraint.Kind = Model.Unconstrained;
      begin
         for Target of Document.Declarations loop
            if Model.Image (Target.Stable_ID)
              = Model.Image (Child.Declaration_ID)
            then
               if (Target.Kind = Model.Access_Type
                   or else Known_Boolean_Equals
                     (Target.Facts, Model.Contains_Access_Fact, True))
                 and then Known_Boolean_Equals
                   (Owner.Facts, Model.Contains_Access_Fact, False)
               then
                  Add (Invalid_Fact, Path, "contained access contradicts owner contains_access=false");
               end if;
               if (Known_Boolean_Equals
                     (Target.Facts, Model.Controlled_Fact, True)
                   or else Known_Boolean_Equals
                     (Target.Facts, Model.Contains_Controlled_Fact, True))
                 and then Known_Boolean_Equals
                   (Owner.Facts, Model.Contains_Controlled_Fact, False)
               then
                  Add (Invalid_Fact, Path, "controlled contained type contradicts owner fact");
               end if;
               if Known_Boolean_Equals
                 (Target.Facts, Model.Limited_Fact, True)
                 and then Known_Boolean_Equals
                   (Owner.Facts, Model.Limited_Fact, False)
               then
                  Add (Invalid_Fact, Path, "limited contained type contradicts owner fact");
               end if;
               if Unconstrained_Ref
                 and then Known_Boolean_Equals
                   (Target.Facts, Model.Definite_Fact, False)
                 and then Known_Boolean_Equals
                   (Owner.Facts, Model.Definite_Fact, True)
               then
                  Add (Invalid_Fact, Path, "indefinite contained type contradicts owner fact");
               end if;
            end if;
         end loop;
      end Check_Contained_Risk;

      procedure Check_Required_Declaration_Facts
        (Declaration : Model.Type_Declaration;
         Path        : String)
      is
         type Required_Fact_Array is array (Positive range <>) of Model.Fact_Name;
         Required : constant Required_Fact_Array :=
           [Model.Definite_Fact,
            Model.Limited_Fact,
            Model.Tagged_Fact,
            Model.Class_Wide_Fact,
            Model.Abstract_Fact,
            Model.Contains_Access_Fact,
            Model.Task_Fact,
            Model.Protected_Fact,
            Model.Controlled_Fact,
            Model.Contains_Controlled_Fact];
         function Is_Core (Name : Model.Fact_Name) return Boolean is
           (Name in Model.Definite_Fact
              | Model.Limited_Fact
              | Model.Tagged_Fact
              | Model.Class_Wide_Fact
              | Model.Abstract_Fact
              | Model.Contains_Access_Fact
              | Model.Task_Fact
              | Model.Protected_Fact
              | Model.Controlled_Fact
              | Model.Contains_Controlled_Fact);
         function Is_Applicable_Shape_Fact
           (Name : Model.Fact_Name) return Boolean
         is
         begin
            case Declaration.Kind is
               when Model.Array_Type =>
                  return Name = Model.Constrained_Fact;
               when Model.Signed_Integer | Model.Enumeration
                  | Model.Boolean_Type | Model.Character_Type =>
                  return Name = Model.Predicate_Fact;
               when Model.Modular_Integer =>
                  return Name in Model.Modulus_Fact | Model.Predicate_Fact;
               when Model.Floating_Point =>
                  return Name in Model.Digits_Fact | Model.Predicate_Fact;
               when Model.Ordinary_Fixed_Point =>
                  return Name in Model.Delta_Fact | Model.Small_Fact
                    | Model.Predicate_Fact;
               when Model.Decimal_Fixed_Point =>
                  return Name in Model.Delta_Fact | Model.Digits_Fact
                    | Model.Small_Fact | Model.Predicate_Fact;
               when Model.Access_Type =>
                  return Name = Model.Null_Exclusion_Fact;
               when others =>
                  return False;
            end case;
         end Is_Applicable_Shape_Fact;
         procedure Require_Shape (Name : Model.Fact_Name) is
         begin
            if not Has_Compatible_Fact (Declaration.Facts, Name) then
               Add
                 (Missing_Mandatory_Fact,
                  Path & "/shape/" & Model.Fact_Key (Name),
                  "structural model requires an explicit applicable shape fact");
            end if;
         end Require_Shape;
         procedure Require_Known_Shape
           (Name    : Model.Fact_Name;
            Message : String) is
         begin
            if Has_Compatible_Fact (Declaration.Facts, Name)
              and then not Has_Known_Fact (Declaration.Facts, Name)
            then
               Add
                 (Imprecise_Mandatory_Fact,
                  Path & "/shape/" & Model.Fact_Key (Name),
                  Message);
            end if;
         end Require_Known_Shape;
      begin
         for Item of Declaration.Facts loop
            if not Is_Core (Item.Name)
              and then not Is_Applicable_Shape_Fact (Item.Name)
            then
               Add
                 (Invalid_Fact,
                  Path & "/facts/" & Model.Fact_Key (Item.Name),
                  "fact is not part of this declaration shape");
            end if;
         end loop;
         for Name of Required loop
            if not Has_Compatible_Fact (Declaration.Facts, Name) then
               Add
                 (Missing_Mandatory_Fact,
                  Path & "/facts/" & Model.Fact_Key (Name),
                  "structural model requires an explicit core fact slot");
            elsif Profile = Strict_Consumer
              and then not Has_Known_Fact (Declaration.Facts, Name)
            then
               Add
                 (Imprecise_Mandatory_Fact,
                  Path & "/facts/" & Model.Fact_Key (Name),
                  "strict profile requires this core fact to be Known");
            end if;
         end loop;
         case Declaration.Kind is
            when Model.Array_Type =>
               Require_Shape (Model.Constrained_Fact);
            when Model.Signed_Integer | Model.Enumeration
               | Model.Boolean_Type | Model.Character_Type =>
               Require_Shape (Model.Predicate_Fact);
            when Model.Modular_Integer =>
               Require_Shape (Model.Modulus_Fact);
               Require_Shape (Model.Predicate_Fact);
            when Model.Floating_Point =>
               Require_Shape (Model.Digits_Fact);
               Require_Shape (Model.Predicate_Fact);
            when Model.Ordinary_Fixed_Point =>
               Require_Shape (Model.Delta_Fact);
               Require_Shape (Model.Small_Fact);
               Require_Shape (Model.Predicate_Fact);
            when Model.Decimal_Fixed_Point =>
               Require_Shape (Model.Delta_Fact);
               Require_Shape (Model.Digits_Fact);
               Require_Shape (Model.Small_Fact);
               Require_Shape (Model.Predicate_Fact);
            when Model.Access_Type =>
               Require_Shape (Model.Null_Exclusion_Fact);
            when others =>
               null;
         end case;
         if Profile = Strict_Consumer then
            case Declaration.Kind is
               when Model.Array_Type =>
                  Require_Known_Shape
                    (Model.Constrained_Fact,
                     "array constrainedness must be Known");
               when Model.Signed_Integer
                  | Model.Enumeration
                  | Model.Boolean_Type
                  | Model.Character_Type =>
                  Require_Known_Shape
                    (Model.Predicate_Fact,
                     "scalar predicate status must be Known");
               when Model.Modular_Integer =>
                  Require_Known_Shape
                    (Model.Modulus_Fact, "modulus must be Known");
                  Require_Known_Shape
                    (Model.Predicate_Fact, "predicate must be Known");
               when Model.Floating_Point =>
                  Require_Known_Shape
                    (Model.Digits_Fact, "floating digits must be Known");
                  Require_Known_Shape
                    (Model.Predicate_Fact, "predicate must be Known");
               when Model.Ordinary_Fixed_Point | Model.Decimal_Fixed_Point =>
                  Require_Known_Shape
                    (Model.Delta_Fact, "fixed delta must be Known");
                  Require_Known_Shape
                    (Model.Small_Fact, "fixed small must be Known");
                  if Declaration.Kind = Model.Decimal_Fixed_Point then
                     Require_Known_Shape
                       (Model.Digits_Fact, "decimal fixed digits must be Known");
                  end if;
                  Require_Known_Shape
                    (Model.Predicate_Fact, "predicate must be Known");
               when Model.Access_Type =>
                  Require_Known_Shape
                    (Model.Null_Exclusion_Fact,
                     "access null exclusion must be Known");
               when others =>
                  null;
            end case;
         end if;
      end Check_Required_Declaration_Facts;

      procedure Check_Constraint
        (Value : Model.Constraint_Access;
         Path  : String;
         Depth : Natural := 0);
      procedure Check_Constraint_Value
        (Value : Model.Constraint_Shape;
         Path  : String;
         Depth : Natural := 0);

      procedure Check_Array_Dimension
        (Dimension : Model.Array_Dimension;
         Path      : String;
         Depth     : Natural := 0);

      function Is_Empty_Fact (Fact : Model.Semantic_Fact) return Boolean is
      begin
         return Fact.Status = Model.Unknown
           and then Model.US.Length (Fact.Code) = 0
           and then Model.US.Length (Fact.Detail) = 0
           and then Fact.Value.Kind = Model.Text_Value
           and then Model.US.Length (Fact.Value.Text_Data) = 0;
      end Is_Empty_Fact;

      function Is_Empty_Type_Reference
        (Ref : Model.Type_Reference) return Boolean is
        (Model.US.Length (Ref.Declaration_ID) = 0
         and then Ref.Use_Site_Constraint = null);

      procedure Expected_Value_Kind
        (Ref   : Model.Type_Reference;
         Found : out Boolean;
         Kind  : out Model.Value_Kind)
      is
      begin
         Found := False;
         Kind := Model.Text_Value;
         for Declaration of Document.Declarations loop
            if Model.Image (Declaration.Stable_ID)
              = Model.Image (Ref.Declaration_ID)
            then
               case Declaration.Kind is
                  when Model.Boolean_Type =>
                     Found := True;
                     Kind := Model.Boolean_Value;
                  when Model.Signed_Integer | Model.Modular_Integer
                     | Model.Enumeration | Model.Character_Type =>
                     Found := True;
                     Kind := Model.Decimal_Integer_Value;
                  when Model.Floating_Point | Model.Ordinary_Fixed_Point
                     | Model.Decimal_Fixed_Point =>
                     Found := True;
                     Kind := Model.Exact_Rational_Value;
                  when Model.Array_Type =>
                     if Declaration.Array_Rank = 1 then
                        for Component of Document.Declarations loop
                           if Model.Image (Component.Stable_ID)
                             = Model.Image
                               (Declaration.Array_Component.Declaration_ID)
                             and then Component.Kind = Model.Character_Type
                           then
                              Found := True;
                              Kind := Model.Text_Value;
                           end if;
                        end loop;
                     end if;
                  when others =>
                     null;
               end case;
            end if;
         end loop;
      end Expected_Value_Kind;

      procedure Check_Known_Value_Against_Type
        (Fact : Model.Semantic_Fact;
         Ref  : Model.Type_Reference;
         Path : String)
      is
         Found : Boolean;
         Kind  : Model.Value_Kind;
      begin
         if Fact.Status /= Model.Known then
            return;
         end if;
         Expected_Value_Kind (Ref, Found, Kind);
         if not Found or else Fact.Value.Kind /= Kind then
            Add
              (Invalid_Fact,
               Path,
               "Known static value is incompatible with its resolved type");
         end if;
      end Check_Known_Value_Against_Type;

      procedure Check_Type_Reference
        (Ref   : Model.Type_Reference;
         Path  : String;
         Depth : Natural := 0)
      is
      begin
         if Model.US.Length (Ref.Declaration_ID) = 0 then
            Add
              (Anonymous_Type_Rejected,
               Path,
               "anonymous type use-site has no stable declaration/view ID");
         elsif not Declaration_Exists (Model.Image (Ref.Declaration_ID)) then
            Add (Unresolved_Reference, Path, "type graph edge does not resolve to a declaration");
         end if;
         if Ref.Use_Site_Constraint /= null then
            if Ref.Use_Site_Constraint.Kind /= Model.Unconstrained
              and then Ref.Use_Site_Constraint.Provenance /= Model.Use_Site
            then
               Add
                 (Invalid_Fact,
                  Path & "/constraint/provenance",
                  "a type-reference constraint must have use-site provenance");
            end if;
            Check_Constraint
              (Ref.Use_Site_Constraint, Path & "/constraint", Depth + 1);
            for Target of Document.Declarations loop
               if Model.Image (Target.Stable_ID)
                 = Model.Image (Ref.Declaration_ID)
               then
                  declare
                     Constraint : Model.Constraint_Shape renames
                       Ref.Use_Site_Constraint.all;
                     Compatible : constant Boolean :=
                       (case Constraint.Kind is
                          when Model.Unconstrained => True,
                          when Model.Scalar_Range_Constraint =>
                            Target.Kind in Model.Signed_Integer
                              | Model.Modular_Integer | Model.Character_Type
                              | Model.Boolean_Type | Model.Enumeration
                              | Model.Floating_Point
                              | Model.Ordinary_Fixed_Point
                              | Model.Decimal_Fixed_Point,
                          when Model.Array_Index_Constraint =>
                            Target.Kind = Model.Array_Type,
                          when Model.Discriminant_Constraint =>
                            Target.Kind = Model.Record_Type,
                          when Model.Digits_Constraint =>
                            Target.Kind in Model.Floating_Point
                              | Model.Decimal_Fixed_Point,
                          when Model.Delta_Constraint =>
                            Target.Kind in Model.Ordinary_Fixed_Point
                              | Model.Decimal_Fixed_Point);
                  begin
                     if not Compatible then
                        Add
                          (Invalid_Fact,
                           Path & "/constraint",
                           "constraint kind is incompatible with referenced declaration");
                     end if;
                     if Constraint.Kind = Model.Scalar_Range_Constraint then
                        declare
                           Found : Boolean;
                           Kind  : Model.Value_Kind;
                        begin
                           Expected_Value_Kind (Ref, Found, Kind);
                           if not Found
                             or else
                               (Constraint.Static_Low.Status = Model.Known
                                and then Constraint.Static_Low.Value.Kind /= Kind)
                             or else
                               (Constraint.Static_High.Status = Model.Known
                                and then Constraint.Static_High.Value.Kind /= Kind)
                           then
                              Add (Invalid_Fact, Path & "/constraint", "evaluated scalar bounds have the wrong value kind");
                           end if;
                        end;
                     end if;
                     if Constraint.Kind = Model.Array_Index_Constraint then
                        declare
                           Dimension : Model.Array_Dimension_Access :=
                             Constraint.First_Dimension;
                           Position  : Natural := 0;
                        begin
                           while Dimension /= null loop
                              if Position >= Natural (Target.Array_Dimensions.Length)
                                or else Model.Image
                                  (Dimension.Index_Subtype.Declaration_ID)
                                  /= Model.Image
                                    (Target.Array_Dimensions (Position)
                                       .Index_Subtype.Declaration_ID)
                              then
                                 Add (Invalid_Fact, Path & "/constraint", "array use-site dimensions disagree with target shape");
                              end if;
                              Position := Position + 1;
                              Dimension := Dimension.Next;
                           end loop;
                           if Position /= Target.Array_Rank then
                              Add (Invalid_Fact, Path & "/constraint", "array use-site rank disagrees with target shape");
                           end if;
                        end;
                     elsif Constraint.Kind = Model.Discriminant_Constraint then
                        declare
                           Association : Model.Discriminant_Association_Access :=
                             Constraint.First_Association;
                        begin
                           while Association /= null loop
                              for Discriminant of Document.Discriminants loop
                                 if Model.Image (Discriminant.Stable_ID)
                                   = Model.Image (Association.Discriminant_ID)
                                   and then Model.Image (Discriminant.Owner_ID)
                                     /= Model.Image (Target.Stable_ID)
                                 then
                                    Add (Invalid_Fact, Path & "/constraint", "discriminant association belongs to another record");
                                 end if;
                              end loop;
                              Association := Association.Next;
                           end loop;
                        end;
                     end if;
                  end;
               end if;
            end loop;
         end if;
      end Check_Type_Reference;

      procedure Check_Expression
        (Value : Model.Expression_Access;
         Path  : String;
         Depth : Natural := 0)
      is
         function Is_One_UTF8_Codepoint (Text : String) return Boolean is
            function Byte (Position : Positive) return Natural is
              (Character'Pos (Text (Position)));
            function Continuation (Position : Positive) return Boolean is
              (Byte (Position) in 16#80# .. 16#BF#);
         begin
            return (Text'Length = 1 and then Byte (1) <= 16#7F#)
              or else
                (Text'Length = 2 and then Byte (1) in 16#C2# .. 16#DF#
                 and then Continuation (2))
              or else
                (Text'Length = 3 and then Byte (1) in 16#E0# .. 16#EF#
                 and then Continuation (2) and then Continuation (3)
                 and then (Byte (1) /= 16#E0# or else Byte (2) >= 16#A0#)
                 and then (Byte (1) /= 16#ED# or else Byte (2) <= 16#9F#))
              or else
                (Text'Length = 4 and then Byte (1) in 16#F0# .. 16#F4#
                 and then Continuation (2) and then Continuation (3)
                 and then Continuation (4)
                 and then (Byte (1) /= 16#F0# or else Byte (2) >= 16#90#)
                 and then (Byte (1) /= 16#F4# or else Byte (2) <= 16#8F#));
         end Is_One_UTF8_Codepoint;
      begin
         if Value = null then
            Add (Invalid_Fact, Path, "resolved expression AST is missing");
            return;
         end if;

         for Ancestor of Expression_Stack loop
            if Ancestor = Value then
               Add (Invalid_Fact, Path, "expression AST contains a cycle");
               return;
            end if;
         end loop;
         Expression_Stack.Append (Value);

         if Model.US.Length (Value.Syntax) = 0
           or else not Model.Is_Valid_UTF8 (Model.Image (Value.Syntax))
         then
            Add (Invalid_Fact, Path & "/syntax", "expression syntax must be nonempty UTF-8");
         end if;

         case Value.Kind is
            when Model.Boolean_Literal =>
               null;
            when Model.Character_Literal =>
               if not Model.Is_Valid_UTF8 (Model.Image (Value.Character_Data))
                 or else not Is_One_UTF8_Codepoint
                   (Model.Image (Value.Character_Data))
               then
                  Add (Invalid_Fact, Path, "character literal must contain one Unicode scalar value");
               end if;
               declare
                  Resolved : Boolean := False;
                  Root     : constant String :=
                    Root_Type_ID
                      (Model.Image (Value.Resolved_Character_Type_ID));
               begin
                  for Declaration of Document.Declarations loop
                     if Model.Image (Declaration.Stable_ID)
                       = Model.Image (Value.Resolved_Character_Type_ID)
                       and then Declaration.Kind = Model.Character_Type
                     then
                        Resolved := True;
                     end if;
                  end loop;
                  if not Resolved
                    or else Root not in
                      "decl:standard.character#public"
                        | "decl:standard.wide_character#public"
                        | "decl:standard.wide_wide_character#public"
                  then
                     Add
                       (Unresolved_Reference,
                        Path & "/resolved_type_id",
                        "v1 character literal must resolve through a predefined Standard character type");
                  end if;
               end;
            when Model.Integer_Literal =>
               if not Model.Is_Canonical_Decimal (Model.Image (Value.Literal)) then
                  Add (Invalid_Fact, Path, "integer literal is not canonical");
               end if;
            when Model.Declaration_Reference =>
               if not Expression_ID_Exists
                 (Model.Image (Value.Referenced_Declaration_ID))
               then
                  Add (Unresolved_Reference, Path, "expression reference is unresolved");
               end if;
            when Model.Unary_Operation =>
               if Value.Unary_Operator not in
                 Model.Plus_Operator | Model.Minus_Operator
                   | Model.Abs_Operator | Model.Not_Operator
               then
                  Add (Invalid_Fact, Path & "/operator", "operator is not unary");
               end if;
               if not Value.Unary_Operator_Is_Predefined then
                  Add
                    (Invalid_Fact,
                     Path & "/operator_resolution",
                     "v1 rejects user-defined operator resolution as Unsupported");
               end if;
               if not Declaration_Exists (Model.Image (Value.Operand_Type_ID))
                 or else not Declaration_Exists
                   (Model.Image (Value.Unary_Result_Type_ID))
               then
                  Add
                    (Unresolved_Reference,
                     Path & "/operator_resolution",
                     "predefined unary operator type edges must resolve");
               end if;
               Check_Expression (Value.Operand, Path & "/operand", Depth + 1);
            when Model.Binary_Operation =>
               if Value.Binary_Operator in
                 Model.Abs_Operator | Model.Not_Operator
               then
                  Add (Invalid_Fact, Path & "/operator", "operator is not binary");
               end if;
               if not Value.Binary_Operator_Is_Predefined then
                  Add
                    (Invalid_Fact,
                     Path & "/operator_resolution",
                     "v1 rejects user-defined operator resolution as Unsupported");
               end if;
               if not Declaration_Exists (Model.Image (Value.Left_Type_ID))
                 or else not Declaration_Exists (Model.Image (Value.Right_Type_ID))
                 or else not Declaration_Exists
                   (Model.Image (Value.Binary_Result_Type_ID))
               then
                  Add
                    (Unresolved_Reference,
                     Path & "/operator_resolution",
                     "predefined binary operator type edges must resolve");
               end if;
               Check_Expression (Value.Left, Path & "/left", Depth + 1);
               Check_Expression (Value.Right, Path & "/right", Depth + 1);
            when Model.Attribute_Reference =>
               Check_Expression (Value.Prefix, Path & "/prefix", Depth + 1);
               declare
                  Arguments : constant Model.Expression_Access_Vectors.Vector :=
                    Value.Attribute_Arguments;
               begin
                  for Argument of Arguments loop
                     Check_Expression
                       (Argument, Path & "/arguments", Depth + 1);
                  end loop;
               end;
               if (Value.Attribute_Name in Model.First_Attribute
                     | Model.Last_Attribute | Model.Length_Attribute
                   and then Value.Attribute_Arguments.Length > 1)
                 or else
                   (Value.Attribute_Name in Model.Pos_Attribute | Model.Val_Attribute
                      | Model.Succ_Attribute | Model.Pred_Attribute
                    and then Value.Attribute_Arguments.Length /= 1)
               then
                  Add (Invalid_Fact, Path & "/arguments", "attribute argument count is invalid");
               end if;
            when Model.Type_Conversion | Model.Qualified_Expression =>
               Check_Type_Reference
                 (Value.Target_Subtype, Path & "/target_subtype", Depth + 1);
               Check_Expression
                 (Value.Converted_Operand, Path & "/operand", Depth + 1);
            when Model.Function_Call =>
               if not Entity_Is_Function
                 (Model.Image (Value.Resolved_Subprogram_ID))
               then
                  Add
                    (Unresolved_Reference,
                     Path & "/resolved_subprogram_id",
                     "call target is not a resolved function entity");
               end if;
               for Index in Value.Call_Arguments.First_Index
                 .. Value.Call_Arguments.Last_Index
               loop
                  Check_Expression
                    (Value.Call_Arguments (Index),
                     Path & "/arguments",
                     Depth + 1);
               end loop;
            when Model.Selected_Component =>
               Check_Expression
                 (Value.Selected_Prefix, Path & "/prefix", Depth + 1);
               if not Expression_ID_Exists (Model.Image (Value.Selector_ID)) then
                  Add
                    (Unresolved_Reference,
                     Path & "/selector_id",
                     "selected component does not resolve");
               end if;
            when Model.Indexed_Component =>
               Check_Expression
                 (Value.Indexed_Prefix, Path & "/prefix", Depth + 1);
               if Value.Index_Expressions.Is_Empty then
                  Add (Invalid_Fact, Path & "/indices", "indexed expression requires at least one index");
               end if;
               for Index in Value.Index_Expressions.First_Index
                 .. Value.Index_Expressions.Last_Index
               loop
                  Check_Expression
                    (Value.Index_Expressions (Index),
                     Path & "/indices",
                     Depth + 1);
               end loop;
            when Model.Unsupported_Expression =>
               declare
                  Marker : constant Model.Semantic_Fact :=
                    (Status => Model.Unsupported,
                     Value  =>
                       (Kind      => Model.Text_Value,
                        Text_Data => Model.To_Text ("")),
                     Code   => Value.Unsupported_Feature_Code,
                     Detail => Model.To_Text (""));
               begin
                  if not Model.Is_Well_Formed (Marker) then
                     Add
                       (Invalid_Fact,
                        Path,
                        "unsupported expression requires a stable feature code");
                  elsif Profile = Strict_Consumer then
                     Add
                       (Imprecise_Mandatory_Fact,
                        Path,
                        "strict consumers reject unsupported structural expressions");
                  end if;
               end;
            when Model.Decimal_Literal =>
               declare
                  Exact : constant Model.Semantic_Fact :=
                    (Status => Model.Known,
                     Value  =>
                       (Kind             => Model.Exact_Rational_Value,
                        Numerator_Data   => Value.Numerator,
                        Denominator_Data => Value.Denominator),
                     Code   => Model.To_Text (""),
                     Detail => Model.To_Text (""));
               begin
                  if not Model.Is_Well_Formed (Exact) then
                     Add (Invalid_Fact, Path, "decimal literal rational is not normalized");
                  end if;
               end;
            when Model.String_Literal =>
               if not Model.Is_Valid_UTF8 (Model.Image (Value.Literal)) then
                  Add (Invalid_Fact, Path, "string literal is not valid UTF-8");
               end if;
         end case;
         Expression_Stack.Delete_Last;
      end Check_Expression;

      function Direct_Literal_Fact
        (Value : Model.Expression_Access) return Model.Semantic_Fact
      is
         Empty : constant Model.Semantic_Fact := (others => <>);
         function Known_Value
           (Item : Model.Typed_Value) return Model.Semantic_Fact is
           ((Status => Model.Known,
             Value => Item,
             Code => Model.To_Text (""),
             Detail => Model.To_Text ("")));
         function Negate (Text : String) return String is
         begin
            if Text = "0" then
               return "0";
            elsif Text (Text'First) = '-' then
               return Text (Text'First + 1 .. Text'Last);
            else
               return '-' & Text;
            end if;
         end Negate;
         function Absolute_Value (Text : String) return String is
           (if Text'Length > 0 and then Text (Text'First) = '-'
            then Text (Text'First + 1 .. Text'Last)
            else Text);
         function Decimal_Image (Number : Natural) return String is
            Raw : constant String := Natural'Image (Number);
         begin
            return Raw (Raw'First + 1 .. Raw'Last);
         end Decimal_Image;
         function UTF8_Position (Text : String) return Natural is
            function Byte (Offset : Natural) return Natural is
              (Character'Pos (Text (Text'First + Offset)));
         begin
            case Text'Length is
               when 1 =>
                  return Byte (0);
               when 2 =>
                  return (Byte (0) mod 32) * 64 + Byte (1) mod 64;
               when 3 =>
                  return (Byte (0) mod 16) * 4_096
                    + (Byte (1) mod 64) * 64 + Byte (2) mod 64;
               when 4 =>
                  return (Byte (0) mod 8) * 262_144
                    + (Byte (1) mod 64) * 4_096
                    + (Byte (2) mod 64) * 64 + Byte (3) mod 64;
               when others =>
                  return 0;
            end case;
         end UTF8_Position;
      begin
         if Value = null then
            return Empty;
         end if;
         case Value.Kind is
            when Model.Boolean_Literal =>
               return Known_Value
                 ((Kind => Model.Boolean_Value,
                   Boolean_Data => Value.Boolean_Data));
            when Model.Character_Literal =>
               if Model.Is_Valid_UTF8 (Model.Image (Value.Character_Data))
                 and then Model.Image (Value.Character_Data)'Length in 1 .. 4
               then
                  return Known_Value
                    ((Kind => Model.Decimal_Integer_Value,
                      Decimal_Data =>
                        Model.To_Text
                          (Decimal_Image
                             (UTF8_Position
                                (Model.Image (Value.Character_Data))))));
               end if;
               return Empty;
            when Model.Integer_Literal =>
               return Known_Value
                 ((Kind => Model.Decimal_Integer_Value,
                   Decimal_Data => Value.Literal));
            when Model.Decimal_Literal =>
               return Known_Value
                 ((Kind => Model.Exact_Rational_Value,
                   Numerator_Data => Value.Numerator,
                   Denominator_Data => Value.Denominator));
            when Model.String_Literal =>
               return Known_Value
                 ((Kind => Model.Text_Value, Text_Data => Value.Literal));
            when Model.Unary_Operation =>
               declare
                  Operand : constant Model.Semantic_Fact :=
                    Direct_Literal_Fact (Value.Operand);
               begin
                  if Operand.Status /= Model.Known then
                     return Empty;
                  end if;
                  case Value.Unary_Operator is
                     when Model.Plus_Operator =>
                        if Operand.Value.Kind in
                          Model.Decimal_Integer_Value | Model.Exact_Rational_Value
                        then
                           return Operand;
                        end if;
                     when Model.Minus_Operator =>
                        if Operand.Value.Kind = Model.Decimal_Integer_Value then
                           return Known_Value
                             ((Kind => Model.Decimal_Integer_Value,
                               Decimal_Data =>
                                 Model.To_Text
                                   (Negate
                                      (Model.Image
                                         (Operand.Value.Decimal_Data)))));
                        elsif Operand.Value.Kind = Model.Exact_Rational_Value then
                           return Known_Value
                             ((Kind => Model.Exact_Rational_Value,
                               Numerator_Data =>
                                 Model.To_Text
                                   (Negate
                                      (Model.Image
                                         (Operand.Value.Numerator_Data))),
                               Denominator_Data =>
                                 Operand.Value.Denominator_Data));
                        end if;
                     when Model.Abs_Operator =>
                        if Operand.Value.Kind = Model.Decimal_Integer_Value then
                           return Known_Value
                             ((Kind => Model.Decimal_Integer_Value,
                               Decimal_Data =>
                                 Model.To_Text
                                   (Absolute_Value
                                      (Model.Image
                                         (Operand.Value.Decimal_Data)))));
                        elsif Operand.Value.Kind = Model.Exact_Rational_Value then
                           return Known_Value
                             ((Kind => Model.Exact_Rational_Value,
                               Numerator_Data =>
                                 Model.To_Text
                                   (Absolute_Value
                                      (Model.Image
                                         (Operand.Value.Numerator_Data))),
                               Denominator_Data =>
                                 Operand.Value.Denominator_Data));
                        end if;
                     when Model.Not_Operator =>
                        if Operand.Value.Kind = Model.Boolean_Value then
                           return Known_Value
                             ((Kind => Model.Boolean_Value,
                               Boolean_Data =>
                                 not Operand.Value.Boolean_Data));
                        end if;
                     when others =>
                        null;
                  end case;
               end;
               return Empty;
            when others =>
               return Empty;
         end case;
      end Direct_Literal_Fact;

      function Same_Value
        (Left, Right : Model.Typed_Value) return Boolean is
      begin
         if Left.Kind /= Right.Kind then
            return False;
         end if;
         case Left.Kind is
            when Model.Boolean_Value =>
               return Left.Boolean_Data = Right.Boolean_Data;
            when Model.Decimal_Integer_Value =>
               return Model.Image (Left.Decimal_Data)
                 = Model.Image (Right.Decimal_Data);
            when Model.Exact_Rational_Value =>
               return Model.Image (Left.Numerator_Data)
                   = Model.Image (Right.Numerator_Data)
                 and then Model.Image (Left.Denominator_Data)
                   = Model.Image (Right.Denominator_Data);
            when Model.Text_Value =>
               return Model.Image (Left.Text_Data) = Model.Image (Right.Text_Data);
            when Model.Expression_Value =>
               return False;
         end case;
      end Same_Value;

      procedure Check_Direct_Literal_Agreement
        (Expression : Model.Expression_Access;
         Fact       : Model.Semantic_Fact;
         Path       : String)
      is
         Direct : constant Model.Semantic_Fact :=
           Direct_Literal_Fact (Expression);
      begin
         if Fact.Status = Model.Known
           and then Direct.Status = Model.Known
           and then not Same_Value (Direct.Value, Fact.Value)
         then
            Add
              (Invalid_Fact,
               Path,
               "evaluated fact contradicts its direct literal expression");
         end if;
      end Check_Direct_Literal_Agreement;

      procedure Check_Typed_Value
        (Value : Model.Typed_Value;
         Path  : String)
      is
         As_Fact : constant Model.Semantic_Fact :=
           (Status => Model.Known,
            Value  => Value,
            Code   => Model.To_Text (""),
            Detail => Model.To_Text (""));
      begin
         if not Model.Is_Well_Formed (As_Fact) then
            Add (Invalid_Fact, Path, "typed value is not canonical");
         elsif Value.Kind = Model.Expression_Value then
            Check_Expression (Value.Expression_Data, Path & "/expression");
         end if;
      end Check_Typed_Value;

      procedure Check_Constraint
        (Value : Model.Constraint_Access;
         Path  : String;
         Depth : Natural := 0)
      is
      begin
         if Value = null then
            return;
         end if;
         for Ancestor of Constraint_Stack loop
            if Ancestor = Value then
               Add (Invalid_Fact, Path, "constraint graph contains a cycle");
               return;
            end if;
         end loop;
         Constraint_Stack.Append (Value);
         Check_Constraint_Value (Value.all, Path, Depth + 1);
         Constraint_Stack.Delete_Last;
      end Check_Constraint;

      procedure Check_Constraint_Value
        (Value : Model.Constraint_Shape;
         Path  : String;
         Depth : Natural := 0)
      is
      begin
         if (Value.Kind = Model.Unconstrained
             and then Value.Provenance /= Model.No_Constraint)
           or else (Value.Kind /= Model.Unconstrained
                    and then Value.Provenance = Model.No_Constraint)
         then
            Add
              (Invalid_Fact,
               Path & "/provenance",
               "constraint kind and provenance disagree");
         end if;
         declare
            Scalar_Payload_Empty : constant Boolean :=
              Value.Low = null and then Value.High = null;
            Common_Facts_Empty : constant Boolean :=
              Is_Empty_Fact (Value.Staticness)
                and then Is_Empty_Fact (Value.Static_Low)
                and then Is_Empty_Fact (Value.Static_High)
                and then Is_Empty_Fact (Value.Static_Value)
                and then Is_Empty_Fact (Value.Secondary_Value)
                and then Is_Empty_Fact (Value.Predicate);
         begin
            if (Value.Kind = Model.Unconstrained
                and then
                  (not Scalar_Payload_Empty
                   or else Value.First_Dimension /= null
                   or else Value.First_Association /= null
                   or else not Common_Facts_Empty))
              or else
                (Value.Kind = Model.Scalar_Range_Constraint
                 and then
                   (Value.First_Dimension /= null
                    or else Value.First_Association /= null
                    or else not Is_Empty_Fact (Value.Static_Value)
                    or else not Is_Empty_Fact (Value.Secondary_Value)))
              or else
                (Value.Kind = Model.Array_Index_Constraint
                 and then
                   (not Scalar_Payload_Empty
                    or else Value.First_Association /= null
                    or else not Common_Facts_Empty))
              or else
                (Value.Kind = Model.Discriminant_Constraint
                 and then
                   (not Scalar_Payload_Empty
                    or else Value.First_Dimension /= null
                    or else not Common_Facts_Empty))
              or else
                (Value.Kind = Model.Digits_Constraint
                 and then
                   (Value.High /= null
                    or else Value.First_Dimension /= null
                    or else Value.First_Association /= null
                    or else not Is_Empty_Fact (Value.Staticness)
                    or else not Is_Empty_Fact (Value.Static_Low)
                    or else not Is_Empty_Fact (Value.Static_High)
                    or else not Is_Empty_Fact (Value.Secondary_Value)
                    or else not Is_Empty_Fact (Value.Predicate)))
              or else
                (Value.Kind = Model.Delta_Constraint
                 and then
                   (Value.High /= null
                    or else Value.First_Dimension /= null
                    or else Value.First_Association /= null
                    or else not Is_Empty_Fact (Value.Staticness)
                    or else not Is_Empty_Fact (Value.Static_Low)
                    or else not Is_Empty_Fact (Value.Static_High)
                    or else not Is_Empty_Fact (Value.Predicate)))
            then
               Add
                 (Invalid_Fact,
                  Path,
                  "constraint carries inactive payload that has no canonical JSON representation");
            end if;
         end;
         case Value.Kind is
            when Model.Unconstrained =>
               null;
            when Model.Scalar_Range_Constraint =>
               Check_Expression (Value.Low, Path & "/low");
               Check_Expression (Value.High, Path & "/high");
               if not Model.Is_Compatible
                 (Model.Constraint_Staticness_Fact, Value.Staticness)
                 or else not Model.Is_Compatible
                   (Model.Predicate_Fact, Value.Predicate)
                 or else not Model.Is_Well_Formed (Value.Static_Low)
                 or else not Model.Is_Well_Formed (Value.Static_High)
               then
                  Add (Invalid_Fact, Path, "constraint facts are malformed");
               elsif Profile = Strict_Consumer
                 and then
                   (Value.Staticness.Status /= Model.Known
                    or else Value.Predicate.Status /= Model.Known
                    or else Value.Static_Low.Status /= Model.Known
                    or else Value.Static_High.Status /= Model.Known)
               then
                  Add
                    (Imprecise_Mandatory_Fact,
                     Path,
                     "range staticness, evaluated bounds, and predicate status must be Known");
               end if;
               if Value.Staticness.Status = Model.Known
                 and then Value.Staticness.Value.Boolean_Data
                 and then
                   (Value.Static_Low.Status /= Model.Known
                    or else Value.Static_High.Status /= Model.Known)
               then
                  Add (Invalid_Fact, Path, "Known static range requires exact evaluated bounds");
               end if;
               Check_Direct_Literal_Agreement
                 (Value.Low, Value.Static_Low, Path & "/static_low");
               Check_Direct_Literal_Agreement
                 (Value.High, Value.Static_High, Path & "/static_high");
            when Model.Array_Index_Constraint =>
               declare
                  Dimension : Model.Array_Dimension_Access :=
                    Value.First_Dimension;
                  Count : Natural := 0;
                  Seen  : Dimension_Access_Vectors.Vector;
               begin
                  if Dimension = null then
                     Add (Invalid_Fact, Path, "array use-site constraint has no dimensions");
                  end if;
                  while Dimension /= null loop
                     if (for some Prior of Seen => Prior = Dimension) then
                        Add (Invalid_Fact, Path, "array dimension list contains a cycle");
                        exit;
                     end if;
                     Seen.Append (Dimension);
                     if Dimension.Position /= Count + 1 then
                        Add
                          (Duplicate_Declaration_Order,
                           Path & "/dimensions",
                           "array dimension positions must be dense from one");
                     end if;
                     Check_Array_Dimension
                       (Dimension.all, Path, Depth + 1);
                     if Dimension.Constraint.Kind /= Model.Unconstrained
                       and then Dimension.Constraint.Provenance /= Model.Use_Site
                     then
                        Add
                          (Invalid_Fact,
                           Path & "/index_constraint/provenance",
                           "use-site array dimensions require use_site provenance");
                     end if;
                     Dimension := Dimension.Next;
                     Count := Count + 1;
                  end loop;
               end;
            when Model.Discriminant_Constraint =>
               declare
                  Association : Model.Discriminant_Association_Access :=
                    Value.First_Association;
                  Count : Natural := 0;
                  Previous_ID : Model.Text;
                  Seen : Association_Access_Vectors.Vector;
               begin
                  if Association = null then
                     Add (Invalid_Fact, Path, "discriminant constraint requires at least one association");
                  end if;
                  while Association /= null loop
                     if (for some Prior of Seen => Prior = Association) then
                        Add (Invalid_Fact, Path, "discriminant association list contains a cycle");
                        exit;
                     end if;
                     Seen.Append (Association);
                     if Count > 0
                       and then Model.Image (Association.Discriminant_ID)
                         <= Model.Image (Previous_ID)
                     then
                        Add
                          (Duplicate_Declaration_Order,
                           Path & "/associations",
                           "discriminant associations must be unique and sorted by ID");
                     end if;
                     if not Discriminant_Exists
                       (Model.Image (Association.Discriminant_ID))
                     then
                        Add (Unresolved_Reference, Path, "discriminant association is unresolved");
                     end if;
                     Check_Expression
                       (Association.Expression, Path & "/expression");
                     if not Model.Is_Compatible
                       (Model.Constraint_Staticness_Fact,
                        Association.Staticness)
                     then
                        Add (Invalid_Fact, Path, "discriminant association staticness is malformed");
                     elsif Profile = Strict_Consumer
                       and then Association.Staticness.Status /= Model.Known
                     then
                        Add
                          (Imprecise_Mandatory_Fact,
                           Path,
                           "discriminant association staticness must be Known");
                     elsif Association.Staticness.Status = Model.Known
                       and then Association.Staticness.Value.Boolean_Data
                         /= Association.Static_Value_Present
                     then
                        Add
                          (Invalid_Fact,
                           Path,
                           "discriminant static-value presence must agree with staticness");
                     end if;
                     if Association.Static_Value_Present then
                        if not Model.Is_Well_Formed (Association.Static_Value) then
                           Add (Invalid_Fact, Path, "discriminant association value is malformed");
                        elsif Profile = Strict_Consumer
                          and then Association.Static_Value.Status /= Model.Known
                        then
                           Add
                             (Imprecise_Mandatory_Fact,
                              Path,
                              "discriminant association value must be Known");
                        end if;
                        for Discriminant of Document.Discriminants loop
                           if Model.Image (Discriminant.Stable_ID)
                             = Model.Image (Association.Discriminant_ID)
                           then
                              Check_Known_Value_Against_Type
                                (Association.Static_Value,
                                 Discriminant.Discriminant_Type,
                                 Path & "/static_value");
                           end if;
                        end loop;
                        Check_Direct_Literal_Agreement
                          (Association.Expression,
                           Association.Static_Value,
                           Path & "/static_value");
                     end if;
                     Previous_ID := Association.Discriminant_ID;
                     Association := Association.Next;
                     Count := Count + 1;
                  end loop;
               end;
            when Model.Digits_Constraint | Model.Delta_Constraint =>
               Check_Expression (Value.Low, Path & "/value");
               if not Model.Is_Compatible
                 ((if Value.Kind = Model.Digits_Constraint
                   then Model.Digits_Fact
                   else Model.Delta_Fact),
                  Value.Static_Value)
               then
                  Add (Invalid_Fact, Path, "constraint static value is malformed");
               elsif Profile = Strict_Consumer
                 and then Value.Static_Value.Status /= Model.Known
               then
                  Add
                    (Imprecise_Mandatory_Fact,
                     Path,
                     "digits or delta value must be Known");
               end if;
               Check_Direct_Literal_Agreement
                 (Value.Low, Value.Static_Value, Path & "/static_value");
               if Value.Kind = Model.Delta_Constraint
                 and then not Model.Is_Compatible
                   (Model.Small_Fact, Value.Secondary_Value)
               then
                  Add (Invalid_Fact, Path, "delta constraint small value is malformed");
               elsif Value.Kind = Model.Delta_Constraint
                 and then Profile = Strict_Consumer
                 and then Value.Secondary_Value.Status /= Model.Known
               then
                  Add
                    (Imprecise_Mandatory_Fact,
                     Path,
                     "small value must be Known");
               end if;
         end case;
      end Check_Constraint_Value;

      procedure Check_Array_Dimension
        (Dimension : Model.Array_Dimension;
         Path      : String;
         Depth     : Natural := 0)
      is
         Found : Boolean;
         Kind  : Model.Value_Kind;
      begin
         Check_Type_Reference
           (Dimension.Index_Subtype, Path & "/index_subtype", Depth + 1);
         if not Declaration_Is_Discrete
           (Model.Image (Dimension.Index_Subtype.Declaration_ID))
         then
            Add
              (Invalid_Fact,
               Path & "/index_subtype",
               "array index subtype must resolve to a discrete type");
         end if;
         Check_Constraint_Value
           (Dimension.Constraint, Path & "/index_constraint", Depth + 1);
         if Dimension.Constraint.Kind not in
           Model.Unconstrained | Model.Scalar_Range_Constraint
         then
            Add
              (Invalid_Fact,
               Path & "/index_constraint",
               "an array dimension accepts only no constraint or a scalar range");
         elsif Dimension.Constraint.Kind = Model.Scalar_Range_Constraint then
            Expected_Value_Kind (Dimension.Index_Subtype, Found, Kind);
            if not Found
              or else
                (Dimension.Constraint.Static_Low.Status = Model.Known
                 and then Dimension.Constraint.Static_Low.Value.Kind /= Kind)
              or else
                (Dimension.Constraint.Static_High.Status = Model.Known
                 and then Dimension.Constraint.Static_High.Value.Kind /= Kind)
            then
               Add
                 (Invalid_Fact,
                  Path & "/index_constraint",
                  "array index bounds are incompatible with the index subtype");
            end if;
         end if;
      end Check_Array_Dimension;

      function Length_Prefix (Value : String) return String is
         Image : constant String := Natural'Image (Value'Length);
      begin
         return (if Image (Image'First) = ' '
                 then Image (Image'First + 1 .. Image'Last)
                 else Image)
           & ":" & Value;
      end Length_Prefix;

      function Fact_Semantic_Key (Fact : Model.Semantic_Fact) return String is
      begin
         case Fact.Status is
            when Model.Unknown | Model.Unsupported =>
               return Model.Fact_Status'Image (Fact.Status) & ":"
                 & Length_Prefix (Model.Image (Fact.Code));
            when Model.Known =>
               case Fact.Value.Kind is
                  when Model.Boolean_Value =>
                     return "KNOWN:BOOLEAN:"
                       & Boolean'Image (Fact.Value.Boolean_Data);
                  when Model.Decimal_Integer_Value =>
                     return "KNOWN:INTEGER:"
                       & Length_Prefix (Model.Image (Fact.Value.Decimal_Data));
                  when Model.Exact_Rational_Value =>
                     return "KNOWN:RATIONAL:"
                       & Length_Prefix (Model.Image (Fact.Value.Numerator_Data))
                       & Length_Prefix (Model.Image (Fact.Value.Denominator_Data));
                  when Model.Text_Value =>
                     return "KNOWN:TEXT:"
                       & Length_Prefix (Model.Image (Fact.Value.Text_Data));
                  when Model.Expression_Value =>
                     return "KNOWN:EXPRESSION";
               end case;
         end case;
      end Fact_Semantic_Key;

      function Named_Fact_Equals
        (Facts : Model.Fact_Vectors.Vector;
         Name  : Model.Fact_Name;
         Other : Model.Semantic_Fact) return Boolean
      is
      begin
         for Item of Facts loop
            if Item.Name = Name then
               return Fact_Semantic_Key (Item.Fact)
                 = Fact_Semantic_Key (Other);
            end if;
         end loop;
         return False;
      end Named_Fact_Equals;

      function Type_Reference_Key
        (Ref : Model.Type_Reference; Depth : Natural := 0) return String;

      function Expression_Key
        (Value : Model.Expression_Access; Depth : Natural := 0) return String
      is
         Result : Model.Text;
      begin
         if Value = null then
            return "NULL";
         end if;
         for Ancestor of Key_Expression_Stack loop
            if Ancestor = Value then
               return "CYCLE";
            end if;
         end loop;
         Key_Expression_Stack.Append (Value);
         Model.US.Append (Result, Model.Expression_Kind'Image (Value.Kind) & ":");
         case Value.Kind is
            when Model.Boolean_Literal =>
               Model.US.Append (Result, Boolean'Image (Value.Boolean_Data));
            when Model.Character_Literal =>
               Model.US.Append
                 (Result,
                  Length_Prefix (Model.Image (Value.Resolved_Character_Type_ID))
                    & Length_Prefix (Model.Image (Value.Character_Data)));
            when Model.Integer_Literal | Model.String_Literal =>
               Model.US.Append (Result, Length_Prefix (Model.Image (Value.Literal)));
            when Model.Decimal_Literal =>
               Model.US.Append
                 (Result,
                  Length_Prefix (Model.Image (Value.Numerator))
                    & Length_Prefix (Model.Image (Value.Denominator)));
            when Model.Declaration_Reference =>
               Model.US.Append
                 (Result,
                  Length_Prefix (Model.Image (Value.Referenced_Declaration_ID)));
            when Model.Unary_Operation =>
               Model.US.Append
                 (Result,
                  Model.Operator_Kind'Image (Value.Unary_Operator) & ":"
                    & Length_Prefix (Model.Image (Value.Operand_Type_ID))
                    & Length_Prefix
                      (Model.Image (Value.Unary_Result_Type_ID))
                    & Length_Prefix (Expression_Key (Value.Operand, Depth + 1)));
            when Model.Binary_Operation =>
               Model.US.Append
                 (Result,
                  Model.Operator_Kind'Image (Value.Binary_Operator) & ":"
                    & Length_Prefix (Model.Image (Value.Left_Type_ID))
                    & Length_Prefix (Model.Image (Value.Right_Type_ID))
                    & Length_Prefix
                      (Model.Image (Value.Binary_Result_Type_ID))
                    & Length_Prefix (Expression_Key (Value.Left, Depth + 1))
                    & Length_Prefix (Expression_Key (Value.Right, Depth + 1)));
            when Model.Attribute_Reference =>
               Model.US.Append
                 (Result,
                  Model.Attribute_Kind'Image (Value.Attribute_Name) & ":"
                    & Length_Prefix (Expression_Key (Value.Prefix, Depth + 1)));
               declare
                  Arguments : constant Model.Expression_Access_Vectors.Vector :=
                    Value.Attribute_Arguments;
               begin
                  for Argument of Arguments loop
                     Model.US.Append
                       (Result,
                        Length_Prefix (Expression_Key (Argument, Depth + 1)));
                  end loop;
               end;
            when Model.Type_Conversion | Model.Qualified_Expression =>
               Model.US.Append
                 (Result,
                  Length_Prefix
                    (Type_Reference_Key (Value.Target_Subtype, Depth + 1))
                    & Length_Prefix
                      (Expression_Key (Value.Converted_Operand, Depth + 1)));
            when Model.Function_Call =>
               Model.US.Append
                 (Result,
                  Length_Prefix (Model.Image (Value.Resolved_Subprogram_ID)));
               declare
                  Arguments : constant Model.Expression_Access_Vectors.Vector :=
                    Value.Call_Arguments;
               begin
                  for Argument of Arguments loop
                     Model.US.Append
                       (Result,
                        Length_Prefix (Expression_Key (Argument, Depth + 1)));
                  end loop;
               end;
            when Model.Selected_Component =>
               Model.US.Append
                 (Result,
                  Length_Prefix
                    (Expression_Key (Value.Selected_Prefix, Depth + 1))
                    & Length_Prefix (Model.Image (Value.Selector_ID)));
            when Model.Indexed_Component =>
               Model.US.Append
                 (Result,
                  Length_Prefix
                    (Expression_Key (Value.Indexed_Prefix, Depth + 1)));
               declare
                  Indices : constant Model.Expression_Access_Vectors.Vector :=
                    Value.Index_Expressions;
               begin
                  for Index of Indices loop
                     Model.US.Append
                       (Result,
                        Length_Prefix (Expression_Key (Index, Depth + 1)));
                  end loop;
               end;
            when Model.Unsupported_Expression =>
               Model.US.Append
                 (Result,
                  Length_Prefix (Model.Image (Value.Unsupported_Feature_Code)));
         end case;
         Key_Expression_Stack.Delete_Last;
         return Model.Image (Result);
      end Expression_Key;

      function Constraint_Value_Key
        (Value : Model.Constraint_Shape; Depth : Natural := 0) return String;

      function Constraint_Key
        (Value : Model.Constraint_Access; Depth : Natural := 0) return String is
      begin
         if Value = null then
            return "NONE";
         end if;
         for Ancestor of Key_Constraint_Stack loop
            if Ancestor = Value then
               return "CYCLE";
            end if;
         end loop;
         Key_Constraint_Stack.Append (Value);
         declare
            Result : constant String := Constraint_Value_Key (Value.all, Depth);
         begin
            Key_Constraint_Stack.Delete_Last;
            return Result;
         end;
      end Constraint_Key;

      function Constraint_Value_Key
        (Value : Model.Constraint_Shape; Depth : Natural := 0) return String
      is
      begin
         if Value.Kind = Model.Unconstrained then
            return "NONE";
         end if;
         case Value.Kind is
            when Model.Unconstrained =>
               return "NONE";
            when Model.Scalar_Range_Constraint =>
               return "RANGE:"
                 & Model.Constraint_Provenance'Image (Value.Provenance) & ":"
                 & Length_Prefix (Expression_Key (Value.Low, Depth + 1))
                 & Length_Prefix (Expression_Key (Value.High, Depth + 1))
                 & Length_Prefix (Fact_Semantic_Key (Value.Staticness))
                 & Length_Prefix (Fact_Semantic_Key (Value.Static_Low))
                 & Length_Prefix (Fact_Semantic_Key (Value.Static_High))
                 & Length_Prefix (Fact_Semantic_Key (Value.Predicate));
            when Model.Array_Index_Constraint =>
               declare
                  Result : Model.Text := Model.To_Text ("ARRAY:");
                  Item   : Model.Array_Dimension_Access := Value.First_Dimension;
                  Seen   : Dimension_Access_Vectors.Vector;
               begin
                  while Item /= null loop
                     if (for some Prior of Seen => Prior = Item) then
                        return "CYCLE";
                     end if;
                     Seen.Append (Item);
                     declare
                        Raw : constant String := Positive'Image (Item.Position);
                     begin
                        Model.US.Append
                          (Result,
                           Raw (Raw'First + 1 .. Raw'Last) & ":"
                             & Length_Prefix
                               (Type_Reference_Key
                                  (Item.Index_Subtype, Depth + 1))
                             & Length_Prefix
                               (Constraint_Value_Key
                                  (Item.Constraint, Depth + 1)));
                     end;
                     Item := Item.Next;
                  end loop;
                  return Model.Image (Result);
               end;
            when Model.Discriminant_Constraint =>
               declare
                  Result : Model.Text := Model.To_Text ("DISCRIMINANTS:");
                  Item : Model.Discriminant_Association_Access :=
                    Value.First_Association;
                  Seen : Association_Access_Vectors.Vector;
               begin
                  while Item /= null loop
                     if (for some Prior of Seen => Prior = Item) then
                        return "CYCLE";
                     end if;
                     Seen.Append (Item);
                     Model.US.Append
                       (Result,
                        Length_Prefix (Model.Image (Item.Discriminant_ID))
                          & Length_Prefix
                            (Expression_Key (Item.Expression, Depth + 1))
                          & Length_Prefix (Fact_Semantic_Key (Item.Staticness))
                          & (if Item.Static_Value_Present
                             then Length_Prefix
                               (Fact_Semantic_Key (Item.Static_Value))
                             else "NULL"));
                     Item := Item.Next;
                  end loop;
                  return Model.Image (Result);
               end;
            when Model.Digits_Constraint | Model.Delta_Constraint =>
               return Model.Constraint_Kind'Image (Value.Kind) & ":"
                 & Length_Prefix (Expression_Key (Value.Low, Depth + 1))
                 & Length_Prefix (Fact_Semantic_Key (Value.Static_Value))
                 & Length_Prefix (Fact_Semantic_Key (Value.Secondary_Value));
         end case;
      end Constraint_Value_Key;

      function Type_Reference_Key
        (Ref : Model.Type_Reference; Depth : Natural := 0) return String is
      begin
         return Length_Prefix (Model.Image (Ref.Declaration_ID))
           & Length_Prefix
             (Constraint_Key (Ref.Use_Site_Constraint, Depth + 1));
      end Type_Reference_Key;

      function Choice_Key (Choice : Model.Discrete_Choice) return String is
      begin
         case Choice.Kind is
            when Model.Expression_Choice =>
               return "0:EXPRESSION:"
                 & Length_Prefix (Expression_Key (Choice.Expression))
                 & Length_Prefix (Fact_Semantic_Key (Choice.Static_Low));
            when Model.Name_Choice =>
               return "1:NAME:" & Length_Prefix (Model.Image (Choice.Resolved_ID))
                 & Length_Prefix (Fact_Semantic_Key (Choice.Static_Low));
            when Model.Range_Choice =>
               return "2:RANGE:" & Length_Prefix (Expression_Key (Choice.Low))
                 & Length_Prefix (Expression_Key (Choice.High))
                 & Length_Prefix (Fact_Semantic_Key (Choice.Static_Low))
                 & Length_Prefix (Fact_Semantic_Key (Choice.Static_High));
            when Model.Subtype_Choice =>
               return "3:SUBTYPE:"
                 & Length_Prefix (Type_Reference_Key (Choice.Resolved_Ref));
            when Model.Others_Choice =>
               return "9:OTHERS";
         end case;
      end Choice_Key;

      function Alternative_Key
        (Alternative : Model.Variant_Alternative) return String
      is
      begin
         if Alternative.Choices.Is_Empty then
            return "";
         end if;
         return Choice_Key (Alternative.Choices.First_Element);
      end Alternative_Key;

      function Variant_Reaches (From_ID, Target_ID : String; Depth : Natural) return Boolean is
      begin
         if Depth > Natural (Document.Variants.Length) then
            return True;
         end if;
         for Part of Document.Variants loop
            if Model.Image (Part.Stable_ID) = From_ID then
               for Alternative of Part.Alternatives loop
                  if Model.US.Length (Alternative.Nested_Variant_ID) > 0 then
                     if Model.Image (Alternative.Nested_Variant_ID) = Target_ID
                       or else Variant_Reaches
                         (Model.Image (Alternative.Nested_Variant_ID), Target_ID, Depth + 1)
                     then
                        return True;
                     end if;
                  end if;
               end loop;
            end if;
         end loop;
         return False;
      end Variant_Reaches;

      function Percent_Encoded (Value : String) return String is
         Hex : constant String := "0123456789abcdef";
         Result : Model.Text;
      begin
         for Character of Value loop
            declare
               Byte : constant Natural := Standard.Character'Pos (Character);
            begin
               Model.US.Append (Result, '%');
               Model.US.Append (Result, Hex (Byte / 16 + 1));
               Model.US.Append (Result, Hex (Byte mod 16 + 1));
            end;
         end loop;
         return Model.Image (Result);
      end Percent_Encoded;

      function Actual_Identity_Value
        (Item : Model.Generic_Actual) return String
      is
         function Scalar_Identity return String is
         begin
            case Item.Semantic_Value.Status is
               when Model.Unknown =>
                  return "unknown:" & Model.Image (Item.Semantic_Value.Code);
               when Model.Unsupported =>
                  return "unsupported:" & Model.Image (Item.Semantic_Value.Code);
               when Model.Known =>
                  case Item.Semantic_Value.Value.Kind is
                     when Model.Boolean_Value =>
                        return
                          (if Item.Semantic_Value.Value.Boolean_Data
                           then "true" else "false");
                     when Model.Decimal_Integer_Value =>
                        return Model.Image
                          (Item.Semantic_Value.Value.Decimal_Data);
                     when Model.Exact_Rational_Value =>
                        return "rat:"
                          & Model.Image
                            (Item.Semantic_Value.Value.Numerator_Data)
                          & ":"
                          & Model.Image
                            (Item.Semantic_Value.Value.Denominator_Data);
                     when Model.Text_Value =>
                        return "text:x"
                          & Percent_Encoded
                            (Model.Image (Item.Semantic_Value.Value.Text_Data));
                     when Model.Expression_Value =>
                        return "";
                  end case;
            end case;
         end Scalar_Identity;
      begin
         case Item.Kind is
            when Model.Type_Actual =>
               if Item.Type_Value.Use_Site_Constraint = null
                 or else Item.Type_Value.Use_Site_Constraint.Kind
                   = Model.Unconstrained
               then
                  return Model.Image (Item.Type_Value.Declaration_ID)
                    & ",constraint=none";
               else
                  return "";
               end if;
            when Model.Package_Actual | Model.Subprogram_Actual =>
               return Model.Image (Item.Declaration_Value);
            when Model.Value_Actual =>
               return Scalar_Identity;
            when Model.Object_Actual =>
               return "object:" & Model.Image (Item.Declaration_Value);
         end case;
      end Actual_Identity_Value;

      function Generic_Bindings (Instance_ID : String) return String is
         Result   : Model.Text;
         Previous : Model.Text;
         First    : Boolean := True;
      begin
         for Actual of Document.Generic_Actuals loop
            if Model.Image (Actual.Instance_ID) = Instance_ID then
               if not First
                 and then Model.Image (Previous)
                   >= Model.Image (Actual.Formal_Canonical_Name)
               then
                  return "";
               end if;
               if not First then
                  Model.US.Append (Result, ',');
               end if;
               Model.US.Append
                  (Result,
                  Model.Image (Actual.Formal_Canonical_Name));
               Model.US.Append (Result, '=');
               Model.US.Append (Result, Model.Image (Actual.Stable_ID));
               Previous := Actual.Formal_Canonical_Name;
               First := False;
            end if;
         end loop;
         return Model.Image (Result);
      end Generic_Bindings;

      function Expanded_Canonical_Name
        (Name         : String;
         Include_Self : Boolean) return String
      is
         Result : Model.Text;
      begin
         for Position in Name'Range loop
            Model.US.Append (Result, Name (Position));
            for Instance of Document.Entities loop
               if Instance.Kind = Model.Package_Entity
                 and then Model.US.Length
                   (Instance.Instantiated_Template_ID) > 0
               then
                  declare
                     Instance_Name : constant String :=
                       Model.Image (Instance.Canonical_Name);
                     Bindings : constant String :=
                       Generic_Bindings (Model.Image (Instance.Stable_ID));
                     Prefix_Matches : constant Boolean :=
                       Position - Name'First + 1 = Instance_Name'Length
                       and then Name'Length >= Instance_Name'Length
                       and then Name
                         (Name'First .. Name'First + Instance_Name'Length - 1)
                           = Instance_Name;
                     Is_Self : constant Boolean :=
                       Name'Length = Instance_Name'Length;
                  begin
                     if Bindings'Length > 0
                       and then Prefix_Matches
                       and then
                         ((Is_Self and then Include_Self)
                          or else
                            (not Is_Self
                             and then Name
                               (Name'First + Instance_Name'Length) = '.'))
                     then
                        Model.US.Append (Result, '[' & Bindings & ']');
                     end if;
                  end;
               end if;
            end loop;
         end loop;
         return Model.Image (Result);
      end Expanded_Canonical_Name;

      function Expected_Declaration_ID
        (Declaration : Model.Type_Declaration) return String
      is
         Name : constant String := Model.Image (Declaration.Canonical_Name);
      begin
         return "decl:" & Expanded_Canonical_Name (Name, True)
           & (case Declaration.View is
                 when Model.Public_View => "#public",
                 when Model.Private_View => "#private",
                 when Model.Full_View => "#full",
                 when Model.Incomplete_View => "#incomplete",
                 when Model.Class_Wide_View => "#class_wide");
      end Expected_Declaration_ID;

      function Expected_Entity_ID
        (Entity : Model.Semantic_Entity) return String
      is
         function Mode_Key (Mode : Model.Parameter_Mode) return String is
           (case Mode is
               when Model.In_Parameter => "in",
               when Model.Out_Parameter => "out",
               when Model.In_Out_Parameter => "in_out");
         function Position_Image (Value : Natural) return String is
            Raw : constant String := Natural'Image (Value);
         begin
            return Raw (Raw'First + 1 .. Raw'Last);
         end Position_Image;
         Profile : Model.Text;
      begin
         if Entity.Callable_Profile_Present then
            Model.US.Append (Profile, "[profile=");
            for Parameter of Entity.Parameters loop
               if Parameter.Position > 0 then
                  Model.US.Append (Profile, ',');
               end if;
               Model.US.Append
                 (Profile,
                  Position_Image (Parameter.Position)
                  & ":" & Mode_Key (Parameter.Mode)
                  & ":" & Model.Image (Parameter.Canonical_Name)
                  & ":" & Model.Image (Parameter.Parameter_Type.Declaration_ID));
            end loop;
            Model.US.Append
              (Profile,
               ",result="
               & (if Entity.Result_Present
                  then Model.Image (Entity.Result_Type.Declaration_ID)
                  else "none")
               & "]");
         elsif Entity.Object_Mode_Present then
            Model.US.Append
              (Profile,
               "[object=" & Mode_Key (Entity.Object_Mode)
               & ",type=" & Model.Image (Entity.Entity_Type.Declaration_ID)
               & "]");
         end if;
         return "decl:"
           & Expanded_Canonical_Name
               (Model.Image (Entity.Canonical_Name), Include_Self => True)
           & Model.Image (Profile) & "#public";
      end Expected_Entity_ID;

      function Canonical_Tail (Name : String) return String is
         First : Positive := Name'First;
      begin
         for Position in Name'Range loop
            if Name (Position) = '.' then
               First := Position + 1;
            end if;
         end loop;
         return Name (First .. Name'Last);
      end Canonical_Tail;

      function Is_Absolute_Path (Value : Model.Text) return Boolean is
         Image : constant String := Model.Image (Value);
      begin
         return Image'Length > 0 and then Image (Image'First) = '/';
      end Is_Absolute_Path;

      function Expected_Named_Child_ID
        (Owner_ID : String;
         Name     : String) return String
      is
         Hash : Natural := 0;
      begin
         for Position in Owner_ID'Range loop
            if Owner_ID (Position) = '#' then
               Hash := Position;
            end if;
         end loop;
         if Hash = 0 or else Name'Length = 0 then
            return "";
         end if;
         return Owner_ID (Owner_ID'First .. Hash - 1) & "."
           & Ada.Characters.Handling.To_Lower (Name)
           & Owner_ID (Hash .. Owner_ID'Last);
      end Expected_Named_Child_ID;

      function Decimal_Image (Value : Natural) return String is
         Raw : constant String := Natural'Image (Value);
      begin
         return Raw (Raw'First + 1 .. Raw'Last);
      end Decimal_Image;

      function Selector_Name (ID : String) return String is
      begin
         for Item of Document.Discriminants loop
            if Model.Image (Item.Stable_ID) = ID then
               return Model.Image (Item.Canonical_Name);
            end if;
         end loop;
         return "";
      end Selector_Name;

   begin
      for Feature of Document.Required_Features loop
         Check_UTF8 (Feature, "/required_features");
      end loop;
      for Feature of Document.Optional_Features loop
         Check_UTF8 (Feature, "/optional_features");
      end loop;
      Check_UTF8 (Document.Context.Extractor_Version, "/context/extractor_version");
      Check_UTF8 (Document.Context.Libadalang_Version, "/context/libadalang_version");
      Check_UTF8 (Document.Context.GNAT_Version, "/context/gnat_version");
      Check_UTF8 (Document.Context.Compiler_Path, "/context/compiler_path");
      Check_UTF8 (Document.Context.Compiler_Identity, "/context/compiler_identity");
      Check_UTF8 (Document.Context.Canonical_GPR_Path, "/context/canonical_gpr_path");
      Check_UTF8 (Document.Context.Legality_Tool_Identity, "/context/legality_check/command/tool_identity");
      Check_UTF8 (Document.Context.Legality_Working_Directory, "/context/legality_check/command/working_directory");
      Check_UTF8 (Document.Context.Consumer_Unit, "/context/accessibility_context/consumer_unit");
      Check_UTF8 (Document.Context.Derivation_Unit, "/context/accessibility_context/derivation_unit");
      Check_UTF8 (Document.Context.Project_Name, "/context/project_name");
      Check_UTF8 (Document.Context.Target, "/context/target");
      Check_UTF8 (Document.Context.Runtime, "/context/runtime_identity");
      for Argument of Document.Context.Legality_Arguments loop
         Check_UTF8 (Argument, "/context/legality_check/command/argv");
      end loop;
      for Binding of Document.Context.Legality_Environment loop
         Check_UTF8 (Binding.Name, "/context/legality_check/command/environment/name");
         Check_UTF8 (Binding.Value, "/context/legality_check/command/environment/value");
      end loop;
      for Binding of Document.Context.Scenario loop
         Check_UTF8 (Binding.Name, "/context/scenario/name");
         Check_UTF8 (Binding.Value, "/context/scenario/value");
      end loop;
      for Value of Document.Context.Compiler_Switches loop
         Check_UTF8 (Value, "/context/effective_project/compiler_switches");
      end loop;
      for Value of Document.Context.Project_Closure loop
         Check_UTF8 (Value, "/context/project_closure");
      end loop;
      for Value of Document.Context.Requested_Units loop
         Check_UTF8 (Value, "/context/requested_units");
      end loop;
      for Source of Document.Context.Configuration_Pragmas loop
         Check_UTF8 (Source.Logical_Name, "/context/effective_project/configuration_pragmas");
      end loop;
      for Source of Document.Context.Project_Files loop
         Check_UTF8 (Source.Logical_Name, "/context/effective_project/project_files");
      end loop;
      for Source of Document.Context.Runtime_Sources loop
         Check_UTF8 (Source.Logical_Name, "/context/effective_project/runtime_sources");
      end loop;
      for Source of Document.Context.Selected_Units loop
         Check_UTF8 (Source.Unit_Name, "/context/effective_project/selected_units/unit_name");
         Check_UTF8 (Source.Logical_Name, "/context/effective_project/selected_units/logical_name");
         Check_UTF8 (Source.Source_Kind, "/context/effective_project/selected_units/source_kind");
      end loop;
      for Declaration of Document.Declarations loop
         Check_UTF8 (Declaration.Display_Name, "/declarations/display_name");
         if Model.US.Length (Declaration.Display_Name) = 0 then
            Add (Invalid_Fact, "/declarations/display_name", "display name must be nonempty");
         end if;
         Check_UTF8 (Declaration.Location.Unit_Name, "/declarations/location/unit_name");
         Check_UTF8 (Declaration.Location.File, "/declarations/location/file");
         for Ref of Declaration.References loop
            Check_UTF8 (Ref.Label, "/declarations/references/label");
         end loop;
      end loop;
      for Component of Document.Components loop
         Check_UTF8 (Component.Name, "/components/name");
         if Model.US.Length (Component.Name) = 0 then
            Add (Invalid_Fact, "/components/name", "component name must be nonempty");
         end if;
         Check_UTF8 (Component.Default_Syntax, "/components/default/syntax");
      end loop;
      for Discriminant of Document.Discriminants loop
         Check_UTF8 (Discriminant.Name, "/discriminants/name");
         if Model.US.Length (Discriminant.Name) = 0 then
            Add (Invalid_Fact, "/discriminants/name", "discriminant name must be nonempty");
         end if;
         Check_UTF8 (Discriminant.Default_Syntax, "/discriminants/default/syntax");
      end loop;
      for Literal of Document.Enumeration_Literals loop
         Check_UTF8 (Literal.Name, "/enum_literals/name");
         if Model.US.Length (Literal.Name) = 0 then
            Add (Invalid_Fact, "/enum_literals/name", "enum literal name must be nonempty");
         end if;
      end loop;
      for Entity of Document.Entities loop
         Check_UTF8 (Entity.Display_Name, "/entities/display_name");
         if Model.US.Length (Entity.Display_Name) = 0 then
            Add (Invalid_Fact, "/entities/display_name", "entity display name must be nonempty");
         end if;
         for Parameter of Entity.Parameters loop
            Check_UTF8 (Parameter.Name, "/entities/callable_profile/parameters/name");
            if Model.US.Length (Parameter.Name) = 0 then
               Add (Invalid_Fact, "/entities/callable_profile/parameters/name", "parameter name must be nonempty");
            end if;
         end loop;
      end loop;
      for Actual of Document.Generic_Actuals loop
         Check_UTF8 (Actual.Formal_Name, "/generic_actuals/formal_name");
         if Model.US.Length (Actual.Formal_Name) = 0 then
            Add (Invalid_Fact, "/generic_actuals/formal_name", "formal name must be nonempty");
         end if;
      end loop;
      for Annotation of Document.Annotations loop
         Check_UTF8 (Annotation.Expression_Syntax, "/annotations/expression_syntax");
      end loop;
      for Part of Document.Variants loop
         for Alternative of Part.Alternatives loop
            for Choice of Alternative.Choices loop
               Check_UTF8 (Choice.Syntax, "/variants/choices/syntax");
               if Model.US.Length (Choice.Syntax) = 0 then
                  Add (Invalid_Fact, "/variants/choices/syntax", "choice syntax must be nonempty");
               end if;
            end loop;
         end loop;
      end loop;
      for Extension of Document.Extensions loop
         Check_UTF8 (Extension.Canonical_JSON, "/extensions");
      end loop;
      if Document.IR_Version /= Current_IR_Version then
         Add (Unsupported_IR_Version, "/ir_version", "reader supports exactly IR version 1");
      end if;

      for Feature of Document.Required_Features loop
         if not Known_Required_Feature (Feature) then
            Add (Unknown_Required_Feature, "/required_features", "unknown mandatory feature: " & Feature);
         end if;
      end loop;
      if Document.Required_Features.Length /= 5 then
         Add
           (Missing_Mandatory_Fact,
            "/required_features",
            "v1 requires the complete five-feature core contract");
      end if;
      if not Is_Sorted_Unique (Document.Required_Features)
        or else not Is_Sorted_Unique (Document.Optional_Features)
      then
         Add (Invalid_Fact, "/required_features", "feature arrays must be sorted and unique");
      end if;
      if not Is_Sorted_Unique (Document.Context.Project_Closure)
        or else not Is_Sorted_Unique (Document.Context.Requested_Units)
        or else not Is_Sorted_Unique (Document.Context.Selected_Units)
        or else not Is_Sorted_Unique
          (Document.Context.Configuration_Pragmas)
        or else not Is_Sorted_Unique (Document.Context.Project_Files)
        or else not Is_Sorted_Unique (Document.Context.Runtime_Sources)
      then
         Add (Invalid_Fact, "/context", "context map/set arrays must be sorted and unique");
      end if;
      declare
         Previous : Model.Text;
         First    : Boolean := True;
      begin
         for Binding of Document.Context.Scenario loop
            if not Is_Scenario_Name (Model.Image (Binding.Name)) then
               Add
                 (Invalid_Fact,
                  "/context/scenario/name",
                  "scenario name is outside the closed lexical grammar");
            end if;
            if not First
              and then Model.Image (Previous) >= Model.Image (Binding.Name)
            then
               Add
                 (Invalid_Fact,
                  "/context/scenario",
                  "scenario names must be sorted and unique");
            end if;
            Previous := Binding.Name;
            First := False;
         end loop;
      end;
      declare
         Previous : Model.Text;
         First    : Boolean := True;
      begin
         for Binding of Document.Context.Legality_Environment loop
            if not Is_Scenario_Name (Model.Image (Binding.Name))
              or else
                (not First
                 and then Model.Image (Previous) >= Model.Image (Binding.Name))
            then
               Add
                 (Invalid_Fact,
                  "/context/legality_check/command/environment",
                  "legality environment names must be canonical, sorted, and unique");
            end if;
            Previous := Binding.Name;
            First := False;
         end loop;
      end;
      if Document.Declarations.Length > 1 then
         for Index in Document.Declarations.First_Index
           .. Document.Declarations.Last_Index - 1
         loop
            if Model.Image (Document.Declarations (Index).Stable_ID)
              >= Model.Image (Document.Declarations (Index + 1).Stable_ID)
            then
               Add (Invalid_Fact, "/declarations", "graph table must be sorted by stable ID");
            end if;
         end loop;
      end if;
      if Document.Components.Length > 1 then
         for Index in Document.Components.First_Index
           .. Document.Components.Last_Index - 1
         loop
            if Model.Image (Document.Components (Index).Stable_ID)
              >= Model.Image (Document.Components (Index + 1).Stable_ID)
            then
               Add (Invalid_Fact, "/components", "graph table must be sorted by stable ID");
            end if;
         end loop;
      end if;
      if Document.Discriminants.Length > 1 then
         for Index in Document.Discriminants.First_Index
           .. Document.Discriminants.Last_Index - 1
         loop
            if Model.Image (Document.Discriminants (Index).Stable_ID)
              >= Model.Image (Document.Discriminants (Index + 1).Stable_ID)
            then
               Add (Invalid_Fact, "/discriminants", "graph table must be sorted by stable ID");
            end if;
         end loop;
      end if;
      if Document.Entities.Length > 1 then
         for Index in Document.Entities.First_Index
           .. Document.Entities.Last_Index - 1
         loop
            if Model.Image (Document.Entities (Index).Stable_ID)
              >= Model.Image (Document.Entities (Index + 1).Stable_ID)
            then
               Add (Invalid_Fact, "/entities", "graph table must be sorted by stable ID");
            end if;
         end loop;
      end if;
      if Document.Enumeration_Literals.Length > 1 then
         for Index in Document.Enumeration_Literals.First_Index
           .. Document.Enumeration_Literals.Last_Index - 1
         loop
            if Model.Image (Document.Enumeration_Literals (Index).Stable_ID)
              >= Model.Image (Document.Enumeration_Literals (Index + 1).Stable_ID)
            then
               Add (Invalid_Fact, "/enum_literals", "graph table must be sorted by stable ID");
            end if;
         end loop;
      end if;
      if Document.Generic_Actuals.Length > 1 then
         for Index in Document.Generic_Actuals.First_Index
           .. Document.Generic_Actuals.Last_Index - 1
         loop
            if Model.Image (Document.Generic_Actuals (Index).Stable_ID)
              >= Model.Image (Document.Generic_Actuals (Index + 1).Stable_ID)
            then
               Add (Invalid_Fact, "/generic_actuals", "graph table must be sorted by stable ID");
            end if;
         end loop;
      end if;
      if Document.Variants.Length > 1 then
         for Index in Document.Variants.First_Index
           .. Document.Variants.Last_Index - 1
         loop
            if Model.Image (Document.Variants (Index).Stable_ID)
              >= Model.Image (Document.Variants (Index + 1).Stable_ID)
            then
               Add (Invalid_Fact, "/variants", "graph table must be sorted by stable ID");
            end if;
         end loop;
      end if;

      for Optional of Document.Optional_Features loop
         declare
            Found : Boolean := False;
         begin
            for Extension of Document.Extensions loop
               Found := Found
                 or else Model.Image (Extension.Namespace) = Optional;
            end loop;
            if not Found then
               Add (Invalid_Fact, "/optional_features", "optional feature has no extension payload");
            end if;
         end;
      end loop;
      for Extension of Document.Extensions loop
         declare
            Found : Boolean := False;
            Same_Namespace : Natural := 0;
         begin
            for Optional of Document.Optional_Features loop
               Found := Found
                 or else Optional = Model.Image (Extension.Namespace);
            end loop;
            if not Found
              or else Model.US.Length (Extension.Canonical_JSON) = 0
            then
               Add
                 (Invalid_Fact,
                  "/extensions",
                  "extension must be listed and carry canonical JSON");
            end if;
            for Other of Document.Extensions loop
               if Model.Image (Other.Namespace)
                 = Model.Image (Extension.Namespace)
               then
                  Same_Namespace := Same_Namespace + 1;
               end if;
            end loop;
            if Same_Namespace /= 1 then
               Add
                 (Invalid_Fact,
                  "/extensions",
                  "extension namespaces must be unique");
            end if;
         end;
      end loop;

      if not Document.Extensions.Is_Empty then
         Add
           (Invalid_Fact,
            "/extensions",
            "the v1 in-memory API fails closed on extensions until a strict codec provides an unforgeable verified representation");
      end if;

      if not Document.Context.Legality_Succeeded then
         Add
           (Invalid_Fact,
            "/context/legality_check/succeeded",
            "extraction requires a successful same-invocation legality check");
      end if;
      if Profile = Strict_Consumer
        and then Document.Context.Kind = Model.Fixture_Context
      then
         Add
           (Invalid_Fact,
            "/context/context_kind",
           "strict production consumers reject synthetic fixture provenance");
      end if;
      if Profile = Strict_Consumer
        and then Document.Context.Kind = Model.Extraction_Context
      then
         Add
           (Invalid_Fact,
            "/context/legality_check",
            "v1 extraction contexts are not strict-admissible until the extractor supplies a verified legality attestation");
      end if;
      if not Model.Is_Canonical_Name
        (Model.Image (Document.Context.Consumer_Unit))
        or else not Model.Is_Canonical_Name
          (Model.Image (Document.Context.Derivation_Unit))
        or else
          Model.Image (Document.Context.Accessibility_Region)
            not in "body" | "private_part" | "public_spec"
      then
         Add
           (Invalid_Fact,
            "/context/accessibility_context",
            "accessibility context requires canonical units and a closed region");
      end if;
      if Model.US.Length (Document.Context.Extractor_Version) = 0
        or else Model.US.Length (Document.Context.Libadalang_Version) = 0
        or else Model.US.Length (Document.Context.GNAT_Version) = 0
        or else Model.US.Length (Document.Context.Compiler_Identity) = 0
        or else Model.US.Length (Document.Context.Project_Name) = 0
        or else Model.US.Length (Document.Context.Target) = 0
        or else Model.US.Length (Document.Context.Runtime) = 0
        or else Document.Context.Legality_Arguments.Is_Empty
        or else Model.US.Length (Document.Context.Legality_Tool_Identity) = 0
        or else Model.US.Length
          (Document.Context.Legality_Working_Directory) = 0
      then
         Add
           (Invalid_Fact,
            "/context",
            "tool/project/runtime identities must be nonempty");
      end if;
      if (Document.Context.Kind = Model.Extraction_Context
          and then
            (not Is_Absolute_Path (Document.Context.Compiler_Path)
             or else not Is_Absolute_Path (Document.Context.Canonical_GPR_Path)))
        or else
          (Document.Context.Kind = Model.Fixture_Context
           and then
             (Model.Image (Document.Context.Compiler_Path) /= "PATH:gprbuild"
              or else Model.Image (Document.Context.Canonical_GPR_Path)
                /= "fixtures/fixtures.gpr"
              or else Model.Image
                (Document.Context.Legality_Command_Fingerprint)
                /= "30727e427da04c78030836e293da3c651e78e07e437e6dfac258b86684e6bfa7"
              or else Natural (Document.Context.Legality_Arguments.Length) /= 5
              or else Document.Context.Legality_Arguments (0) /= "gprbuild"
              or else Document.Context.Legality_Arguments (1) /= "-P"
              or else Document.Context.Legality_Arguments (2)
                /= "../fixtures/fixtures.gpr"
              or else Document.Context.Legality_Arguments (3) /= "-c"
              or else Document.Context.Legality_Arguments (4) /= "-gnatc"
              or else not Document.Context.Legality_Environment.Is_Empty
              or else Model.Image (Document.Context.Legality_Tool_Identity)
                /= "fixture-toolchain"
              or else Model.Image
                (Document.Context.Legality_Working_Directory) /= "tests"))
      then
         Add
           (Invalid_Fact,
            "/context",
            "context kind disagrees with its extraction or fixture legality identity");
      end if;
      if not Is_SHA256
        (Model.Image (Document.Context.Effective_Closure_Digest))
        or else Document.Context.Selected_Units.Is_Empty
        or else Document.Context.Project_Files.Is_Empty
        or else Document.Context.Runtime_Sources.Is_Empty
        or else Document.Context.Requested_Units.Is_Empty
        or else Document.Context.Project_Closure.Is_Empty
      then
         Add
           (Invalid_Fact,
            "/context/effective_project",
            "effective project closure requires a digest and selected units");
      end if;
      if not Is_SHA256
        (Model.Image (Document.Context.Legality_Command_Fingerprint))
      then
         Add
           (Invalid_Fact,
            "/context/legality_check/command_fingerprint",
            "legality command fingerprint must be lowercase SHA-256");
      end if;
      for Source of Document.Context.Selected_Units loop
         declare
            Same_Key : Natural := 0;
            In_Closure : Boolean := False;
         begin
            for Other of Document.Context.Selected_Units loop
               if Model.Image (Other.Unit_Name) = Model.Image (Source.Unit_Name)
                 and then Model.Image (Other.Source_Kind) = Model.Image (Source.Source_Kind)
                 and then Model.Image (Other.Logical_Name) = Model.Image (Source.Logical_Name)
               then
                  Same_Key := Same_Key + 1;
               end if;
            end loop;
            for Unit of Document.Context.Project_Closure loop
               In_Closure := In_Closure or else Unit = Model.Image (Source.Unit_Name);
            end loop;
            if Model.US.Length (Source.Unit_Name) = 0
              or else Model.US.Length (Source.Logical_Name) = 0
              or else Model.Image (Source.Source_Kind) not in "spec" | "body" | "subunit"
              or else not Is_SHA256 (Model.Image (Source.Content_Digest))
              or else Same_Key /= 1
              or else not In_Closure
            then
               Add
                 (Invalid_Fact,
                  "/context/effective_project/selected_units",
                  "selected sources require a closure unit, kind, unique path, and SHA-256 digest");
            end if;
         end;
      end loop;
      for Source of Document.Context.Configuration_Pragmas loop
         declare
            Same_Name : Natural := 0;
         begin
            for Other of Document.Context.Configuration_Pragmas loop
               if Model.Image (Other.Logical_Name)
                 = Model.Image (Source.Logical_Name)
               then
                  Same_Name := Same_Name + 1;
               end if;
            end loop;
            if Model.US.Length (Source.Logical_Name) = 0
              or else not Is_SHA256 (Model.Image (Source.Content_Digest))
              or else Same_Name /= 1
            then
               Add
                 (Invalid_Fact,
                  "/context/effective_project/configuration_pragmas",
                  "configuration names must be nonempty/unique and digests SHA-256");
            end if;
         end;
      end loop;
      for Source of Document.Context.Project_Files loop
         declare
            Same_Name : Natural := 0;
         begin
            for Other of Document.Context.Project_Files loop
               if Model.Image (Other.Logical_Name)
                 = Model.Image (Source.Logical_Name)
               then
                  Same_Name := Same_Name + 1;
               end if;
            end loop;
            if (Document.Context.Kind = Model.Extraction_Context
                and then not Is_Absolute_Path (Source.Logical_Name))
              or else Model.US.Length (Source.Logical_Name) = 0
              or else not Is_SHA256 (Model.Image (Source.Content_Digest))
              or else Same_Name /= 1
            then
               Add
                 (Invalid_Fact,
                  "/context/effective_project/project_files",
                  "project paths must be context-appropriate/unique and digests SHA-256");
            end if;
         end;
      end loop;
      declare
         Root_Project_Count : Natural := 0;
      begin
         for Source of Document.Context.Project_Files loop
            if Model.Image (Source.Logical_Name)
              = Model.Image (Document.Context.Canonical_GPR_Path)
            then
               Root_Project_Count := Root_Project_Count + 1;
            end if;
         end loop;
         if Root_Project_Count /= 1 then
            Add
              (Missing_Mandatory_Fact,
               "/context/effective_project/project_files",
               "project manifest must contain the canonical root GPR exactly once");
         end if;
      end;
      for Source of Document.Context.Runtime_Sources loop
         declare
            Same_Name : Natural := 0;
         begin
            for Other of Document.Context.Runtime_Sources loop
               if Model.Image (Other.Logical_Name)
                 = Model.Image (Source.Logical_Name)
               then
                  Same_Name := Same_Name + 1;
               end if;
            end loop;
            if Model.US.Length (Source.Logical_Name) = 0
              or else not Is_SHA256 (Model.Image (Source.Content_Digest))
              or else Same_Name /= 1
            then
               Add
                 (Invalid_Fact,
                  "/context/effective_project/runtime_sources",
                  "runtime names must be nonempty/unique and digests SHA-256");
            end if;
         end;
      end loop;
      for Unit of Document.Context.Project_Closure loop
         if Unit'Length = 0 then
            Add (Invalid_Fact, "/context/project_closure", "project closure names must be nonempty");
         end if;
      end loop;
      for Unit of Document.Context.Requested_Units loop
         if Unit'Length = 0 then
            Add (Invalid_Fact, "/context/requested_units", "requested unit names must be nonempty");
         end if;
         declare
            In_Closure : Boolean := False;
         begin
            for Closure_Unit of Document.Context.Project_Closure loop
               In_Closure := In_Closure or else Closure_Unit = Unit;
            end loop;
            if not In_Closure then
               Add
                 (Unresolved_Reference,
                  "/context/requested_units",
                  "requested units must belong to the project closure");
            end if;
         end;
      end loop;
      for Unit of Document.Context.Project_Closure loop
         declare
            Matches : Natural := 0;
         begin
            for Source of Document.Context.Selected_Units loop
               if Model.Image (Source.Unit_Name) = Unit then
                  Matches := Matches + 1;
               end if;
            end loop;
            if Matches = 0 then
               Add
                 (Missing_Mandatory_Fact,
                  "/context/effective_project/selected_units",
                  "each closure unit requires at least one selected source digest");
            end if;
         end;
      end loop;

      for Declaration of Document.Declarations loop
         declare
            ID : constant String := Model.Image (Declaration.Stable_ID);
         begin
            Check_ID (ID, "/declarations/" & ID & "/stable_id");
            if ID /= Expected_Declaration_ID (Declaration) then
               Add
                 (Invalid_Semantic_ID,
                  "/declarations/" & ID & "/stable_id",
                  "declaration ID must exactly encode canonical generic bindings and view");
            end if;
            if not Model.Is_Canonical_Name
              (Model.Image (Declaration.Canonical_Name))
              or else Declaration_Name_From_ID (ID)
              /= Model.Image (Declaration.Canonical_Name)
            then
               Add
                 (Invalid_Semantic_ID,
                  "/declarations/" & ID & "/canonical_name",
                  "semantic ID and canonical declaration name disagree");
            end if;
            Check_Facts (Declaration.Facts, "/declarations/" & ID);
            if not Base_Path_Acyclic (ID, ID) then
               Add
                 (Invalid_Fact,
                  "/declarations/" & ID & "/references",
                  "base-subtype and derivation edges must be acyclic");
            end if;
            Check_Required_Declaration_Facts
              (Declaration, "/declarations/" & ID);
            for Name in Model.Fact_Name range
              Model.Modulus_Fact .. Model.Small_Fact
            loop
               if not Known_Fact_Is_Positive (Declaration.Facts, Name) then
                  Add
                    (Invalid_Fact,
                     "/declarations/" & ID & "/facts/"
                       & Model.Fact_Key (Name),
                     "Known modulus, digits, delta, and small values must be positive");
               end if;
            end loop;
            if (Declaration.Form = Model.Private_Declaration_Form
                and then
                  (Declaration.Kind /= Model.Private_Type
                   or else Declaration.View not in
                     Model.Public_View | Model.Private_View))
              or else
                (Declaration.Form = Model.Incomplete_Declaration_Form
                 and then
                   (Declaration.Kind /= Model.Incomplete_Type
                    or else Declaration.View /= Model.Incomplete_View))
              or else
                (Declaration.Form = Model.Class_Wide_Declaration_Form
                 and then
                   (Declaration.Kind /= Model.Class_Wide_Type
                    or else Declaration.View /= Model.Class_Wide_View))
              or else
                (Declaration.Form in
                   Model.Derived_Declaration_Form | Model.Subtype_Declaration_Form
                 and then Declaration.Kind in
                   Model.Interface_Type | Model.Private_Type
                     | Model.Incomplete_Type | Model.Class_Wide_Type)
              or else
                (Declaration.Form = Model.Type_Declaration_Form
                 and then Declaration.Kind in
                   Model.Private_Type | Model.Incomplete_Type
                     | Model.Class_Wide_Type)
            then
               Add
                 (Invalid_Fact,
                  "/declarations/" & ID & "/declaration_form",
                  "declaration form, view, and effective shape disagree");
            end if;
            declare
               procedure Check_Core_Boolean
                 (Name     : Model.Fact_Name;
                  Expected : Boolean)
               is
               begin
                  if Has_Known_Fact (Declaration.Facts, Name)
                    and then not Known_Boolean_Equals
                      (Declaration.Facts, Name, Expected)
                  then
                     Add
                       (Invalid_Fact,
                        "/declarations/" & ID & "/facts/"
                          & Model.Fact_Key (Name),
                        "core fact contradicts declaration form or effective shape");
                  end if;
               end Check_Core_Boolean;
            begin
               Check_Core_Boolean
                 (Model.Class_Wide_Fact,
                  Declaration.Form = Model.Class_Wide_Declaration_Form);
               Check_Core_Boolean
                 (Model.Task_Fact, Declaration.Kind = Model.Task_Type);
               Check_Core_Boolean
                 (Model.Protected_Fact, Declaration.Kind = Model.Protected_Type);
               if Declaration.Kind = Model.Interface_Type then
                  Check_Core_Boolean (Model.Tagged_Fact, True);
                  Check_Core_Boolean (Model.Abstract_Fact, True);
               end if;
               if Declaration.Form = Model.Class_Wide_Declaration_Form then
                  Check_Core_Boolean (Model.Tagged_Fact, True);
               end if;
               if Known_Boolean_Equals
                 (Declaration.Facts, Model.Abstract_Fact, True)
               then
                  Check_Core_Boolean (Model.Tagged_Fact, True);
               end if;
               if Declaration.Kind = Model.Access_Type then
                  Check_Core_Boolean (Model.Contains_Access_Fact, True);
               end if;
               if Declaration.Kind in
                 Model.Signed_Integer | Model.Modular_Integer
                   | Model.Enumeration | Model.Floating_Point
                   | Model.Ordinary_Fixed_Point | Model.Decimal_Fixed_Point
                   | Model.Boolean_Type | Model.Character_Type
                   | Model.Access_Type
               then
                  Check_Core_Boolean (Model.Definite_Fact, True);
               elsif Declaration.Form = Model.Class_Wide_Declaration_Form then
                  Check_Core_Boolean (Model.Definite_Fact, False);
               end if;
               if Declaration.Kind in Model.Task_Type | Model.Protected_Type then
                  Check_Core_Boolean (Model.Limited_Fact, True);
               end if;
            end;
            declare
               Expected_Suffix : constant String :=
                 (case Declaration.View is
                     when Model.Public_View => "#public",
                     when Model.Private_View => "#private",
                     when Model.Full_View => "#full",
                     when Model.Incomplete_View => "#incomplete",
                     when Model.Class_Wide_View => "#class_wide");
            begin
               if ID'Length < Expected_Suffix'Length
                 or else ID (ID'Last - Expected_Suffix'Length + 1 .. ID'Last)
                   /= Expected_Suffix
               then
                  Add
                    (Invalid_Semantic_ID,
                     "/declarations/" & ID & "/view",
                     "declaration view must agree with its semantic ID suffix");
               end if;
            end;
            if not Is_Sorted_Unique (Declaration.Related_View_IDs) then
               Add
                 (Invalid_Fact,
                  "/declarations/" & ID & "/related_view_ids",
                  "related view IDs must be sorted and unique");
            end if;
            declare
               Expected_Related : Natural := 0;
            begin
               for Candidate of Document.Declarations loop
                  if Declaration_Family_Key
                       (Model.Image (Candidate.Stable_ID))
                    = Declaration_Family_Key (ID)
                    and then Model.Image (Candidate.Stable_ID) /= ID
                    and then Candidate.Form /= Model.Class_Wide_Declaration_Form
                    and then Declaration.Form /= Model.Class_Wide_Declaration_Form
                  then
                     Expected_Related := Expected_Related + 1;
                  end if;
               end loop;
               if Natural (Declaration.Related_View_IDs.Length)
                 /= Expected_Related
               then
                  Add
                    (Missing_Mandatory_Fact,
                     "/declarations/" & ID & "/related_view_ids",
                     "related_view_ids must list every other view of the declaration");
               end if;
            end;
            for Related_ID of Declaration.Related_View_IDs loop
               if Related_ID = ID or else not Declaration_Exists (Related_ID) then
                  Add
                    (Unresolved_Reference,
                     "/declarations/" & ID & "/related_view_ids",
                     "related view must resolve to a distinct declaration");
               else
                  for Related of Document.Declarations loop
                     if Model.Image (Related.Stable_ID) = Related_ID then
                        if Declaration_Family_Key
                             (Model.Image (Related.Stable_ID))
                          /= Declaration_Family_Key (ID)
                        then
                           Add
                             (Invalid_Semantic_ID,
                              "/declarations/" & ID & "/related_view_ids",
                              "related views must name the same canonical declaration");
                        end if;
                        declare
                           Reciprocal : Boolean := False;
                        begin
                           for Reverse_ID of Related.Related_View_IDs loop
                              Reciprocal := Reciprocal or else Reverse_ID = ID;
                           end loop;
                           if not Reciprocal then
                              Add
                                (Invalid_Fact,
                                 "/declarations/" & ID & "/related_view_ids",
                                 "related view links must be reciprocal");
                           end if;
                        end;
                     end if;
                  end loop;
               end if;
            end loop;
            if not Model.Is_Well_Formed
              (Declaration.Representation_Available)
              or else not Model.Is_Well_Formed
                (Declaration.Consumer_Can_Name_Components)
              or else
                (Declaration.Representation_Available.Status = Model.Known
                 and then Declaration.Representation_Available.Value.Kind
                   /= Model.Boolean_Value)
              or else
                (Declaration.Consumer_Can_Name_Components.Status = Model.Known
                 and then Declaration.Consumer_Can_Name_Components.Value.Kind
                   /= Model.Boolean_Value)
            then
               Add
                 (Invalid_Fact,
                  "/declarations/" & ID & "/view_access",
                  "view access facts must be well-formed booleans when Known");
            elsif Profile = Strict_Consumer
              and then
                (Declaration.Representation_Available.Status /= Model.Known
                 or else Declaration.Consumer_Can_Name_Components.Status
                   /= Model.Known)
            then
               Add
                 (Imprecise_Mandatory_Fact,
                  "/declarations/" & ID & "/view_access",
                  "strict consumers require exact visibility facts");
            end if;
            if Declaration.Consumer_Can_Name_Components.Status = Model.Known
              and then Declaration.Consumer_Can_Name_Components.Value.Boolean_Data
              and then
                (Declaration.Representation_Available.Status /= Model.Known
                 or else not Declaration.Representation_Available.Value.Boolean_Data)
            then
               Add
                 (Invalid_Fact,
                  "/declarations/" & ID & "/view_access",
                  "component naming cannot exceed representation availability");
            end if;
            if Model.Image (Document.Context.Accessibility_Region) = "public_spec"
              and then Declaration.View = Model.Full_View
              and then Declaration.Consumer_Can_Name_Components.Status
                = Model.Known
              and then Declaration.Consumer_Can_Name_Components.Value.Kind
                = Model.Boolean_Value
              and then Declaration.Consumer_Can_Name_Components.Value.Boolean_Data
            then
               for Related_ID of Declaration.Related_View_IDs loop
                  for Related of Document.Declarations loop
                     if Model.Image (Related.Stable_ID) = Related_ID
                       and then
                         (Related.View = Model.Private_View
                          or else Related.Form
                            = Model.Private_Declaration_Form)
                     then
                        Add
                          (Invalid_Fact,
                           "/declarations/" & ID & "/view_access",
                           "public-spec context cannot name a private completion's components");
                     end if;
                  end loop;
               end loop;
            end if;
            declare
               Previous_Role   : Model.Reference_Role := Model.Base_Subtype_Role;
               Previous_Label  : Model.Text;
               Previous_Target : Model.Text;
               First           : Boolean := True;
            begin
               for Ref of Declaration.References loop
                  Check_Type_Reference
                    (Ref.Target, "/declarations/" & ID & "/references");
                  declare
                     Same_Key : Natural := 0;
                     Current_Target : constant String :=
                       Type_Reference_Key (Ref.Target);
                     Out_Of_Order : constant Boolean :=
                       not First
                       and then
                         (Ref.Role < Previous_Role
                          or else
                            (Ref.Role = Previous_Role
                             and then
                               (Model.Image (Ref.Label)
                                  < Model.Image (Previous_Label)
                                or else
                                  (Model.Image (Ref.Label)
                                     = Model.Image (Previous_Label)
                                   and then Current_Target
                                     <= Model.Image (Previous_Target)))));
                  begin
                     if Out_Of_Order then
                        Add
                          (Invalid_Fact,
                           "/declarations/" & ID & "/references",
                           "references must use canonical role/label/target order");
                     end if;
                     Previous_Role := Ref.Role;
                     Previous_Label := Ref.Label;
                     Previous_Target := Model.To_Text (Current_Target);
                     First := False;
                     for Other of Declaration.References loop
                        if Other.Role = Ref.Role
                          and then Model.Image (Other.Label) = Model.Image (Ref.Label)
                        then
                           Same_Key := Same_Key + 1;
                        end if;
                     end loop;
                     if Same_Key /= 1 then
                        Add
                          (Invalid_Fact,
                           "/declarations/" & ID & "/references",
                           "reference role and label pairs must be unique");
                     end if;
                  end;
                  if Ref.Role = Model.Base_Subtype_Role
                    and then Type_Reference_Key (Ref.Target)
                      /= Type_Reference_Key (Declaration.Base_Subtype)
                  then
                     Add (Invalid_Fact, "/declarations/" & ID & "/references", "base reference contradicts the structural base edge");
                  end if;
               end loop;
            end;
            declare
               Base_Count : Natural := 0;
               Parent_Count : Natural := 0;
            begin
               for Ref of Declaration.References loop
                  if Ref.Role = Model.Base_Subtype_Role then
                     Base_Count := Base_Count + 1;
                  elsif Ref.Role = Model.Parent_Type_Role then
                     Parent_Count := Parent_Count + 1;
                  end if;
               end loop;
               if Declaration.Form in
                 Model.Subtype_Declaration_Form | Model.Derived_Declaration_Form
               then
                  if Base_Count /= 1
                    or else Model.US.Length
                      (Declaration.Base_Subtype.Declaration_ID) = 0
                  then
                     Add
                       (Missing_Mandatory_Fact,
                        "/declarations/" & ID & "/base_subtype",
                        "subtype and derived forms require exactly one structural base edge");
                  end if;
                  if Declaration.Base_Subtype.Use_Site_Constraint /= null
                    and then Declaration.Base_Subtype.Use_Site_Constraint.Kind
                      /= Model.Unconstrained
                  then
                     Add
                       (Invalid_Fact,
                        "/declarations/" & ID & "/base_subtype",
                        "base-subtype edge must be unconstrained");
                  end if;
                  for Base of Document.Declarations loop
                     if Model.Image (Base.Stable_ID)
                       = Model.Image (Declaration.Base_Subtype.Declaration_ID)
                       and then Base.Kind /= Declaration.Kind
                     then
                        Add
                          (Invalid_Fact,
                           "/declarations/" & ID & "/base_subtype",
                           "base subtype and declaration effective kinds disagree");
                     end if;
                  end loop;
               elsif Base_Count /= 0
                 or else Model.US.Length (Declaration.Base_Subtype.Declaration_ID) /= 0
                 or else Declaration.Base_Subtype.Use_Site_Constraint /= null
               then
                  Add (Invalid_Fact, "/declarations/" & ID & "/base_subtype", "non-derived declarations cannot carry inactive base payload");
               end if;
               if Declaration.Form = Model.Class_Wide_Declaration_Form then
                  if Parent_Count /= 1 then
                     Add (Missing_Mandatory_Fact, "/declarations/" & ID & "/references", "class-wide declarations require exactly one parent edge");
                  end if;
                  for Ref of Declaration.References loop
                     if Ref.Role = Model.Parent_Type_Role then
                        for Parent of Document.Declarations loop
                           if Model.Image (Parent.Stable_ID)
                             = Model.Image (Ref.Target.Declaration_ID)
                           then
                              if (Ref.Target.Use_Site_Constraint /= null
                                  and then Ref.Target.Use_Site_Constraint.Kind
                                    /= Model.Unconstrained)
                                or else Parent.Form
                                  = Model.Class_Wide_Declaration_Form
                                or else Declaration_Family_Key
                                  (Model.Image (Parent.Stable_ID))
                                  /= Declaration_Family_Key (ID)
                                or else not Known_Boolean_Equals
                                  (Parent.Facts, Model.Tagged_Fact, True)
                              then
                                 Add
                                   (Invalid_Fact,
                                    "/declarations/" & ID & "/references",
                                    "class-wide parent must be an unconstrained tagged specific view of the same declaration");
                              end if;
                           end if;
                        end loop;
                     end if;
                  end loop;
               elsif Parent_Count /= 0 then
                  Add (Invalid_Fact, "/declarations/" & ID & "/references", "only class-wide declarations may carry a parent edge");
               end if;
            end;
            Check_Constraint_Value
              (Declaration.Constraint,
               "/declarations/" & ID & "/constraint");
            if Declaration.Kind = Model.Record_Type
              and then Declaration.Constraint.Kind
                = Model.Discriminant_Constraint
            then
               declare
                  Association : Model.Discriminant_Association_Access :=
                    Declaration.Constraint.First_Association;
               begin
                  while Association /= null loop
                     for Discriminant of Document.Discriminants loop
                        if Model.Image (Discriminant.Stable_ID)
                          = Model.Image (Association.Discriminant_ID)
                          and then Model.Image (Discriminant.Owner_ID) /= ID
                        then
                           Add
                             (Invalid_Fact,
                              "/declarations/" & ID & "/constraint",
                              "discriminant association belongs to another record");
                        end if;
                     end loop;
                     Association := Association.Next;
                  end loop;
               end;
            end if;
            Check_Constraint_Value
              (Declaration.Digits_Constraint,
               "/declarations/" & ID & "/shape/digits_constraint");
            Check_Constraint_Value
              (Declaration.Delta_Constraint,
               "/declarations/" & ID & "/shape/delta_constraint");
            if Declaration.Form = Model.Type_Declaration_Form
              and then Declaration.Kind = Model.Modular_Integer
            then
               declare
                  Modulus : constant String :=
                    Known_Decimal_Value
                      (Declaration.Facts, Model.Modulus_Fact);
               begin
                  if Modulus'Length = 0
                    or else Declaration.Constraint.Static_Low.Status
                      /= Model.Known
                    or else Declaration.Constraint.Static_High.Status
                      /= Model.Known
                    or else Declaration.Constraint.Static_Low.Value.Kind
                      /= Model.Decimal_Integer_Value
                    or else Declaration.Constraint.Static_High.Value.Kind
                      /= Model.Decimal_Integer_Value
                    or else Model.Image
                      (Declaration.Constraint.Static_Low.Value.Decimal_Data)
                      /= "0"
                    or else Model.Image
                      (Declaration.Constraint.Static_High.Value.Decimal_Data)
                      /= Decimal_Predecessor (Modulus)
                  then
                     Add
                       (Invalid_Fact,
                        "/declarations/" & ID & "/shape/range",
                        "base modular range must be exactly 0 through modulus-1");
                  end if;
               end;
            elsif Declaration.Form = Model.Type_Declaration_Form
              and then Declaration.Kind = Model.Boolean_Type
              and then
                (Declaration.Constraint.Static_Low.Status /= Model.Known
                 or else Declaration.Constraint.Static_High.Status /= Model.Known
                 or else Declaration.Constraint.Static_Low.Value.Kind
                   /= Model.Boolean_Value
                 or else Declaration.Constraint.Static_High.Value.Kind
                   /= Model.Boolean_Value
                 or else Declaration.Constraint.Static_Low.Value.Boolean_Data
                 or else not Declaration.Constraint.Static_High.Value.Boolean_Data)
            then
               Add
                 (Invalid_Fact,
                  "/declarations/" & ID & "/shape/range",
                  "base boolean range must be exactly False through True");
            end if;
            if Declaration.Kind in
              Model.Signed_Integer | Model.Modular_Integer
                | Model.Enumeration | Model.Floating_Point
                | Model.Ordinary_Fixed_Point | Model.Decimal_Fixed_Point
                | Model.Boolean_Type | Model.Character_Type
              and then not Named_Fact_Equals
                (Declaration.Facts,
                 Model.Predicate_Fact,
                 Declaration.Constraint.Predicate)
            then
               Add
                 (Invalid_Fact,
                  "/declarations/" & ID & "/shape/predicate",
                  "shape predicate contradicts effective range predicate");
            end if;
            if Declaration.Kind in
              Model.Floating_Point | Model.Decimal_Fixed_Point
              and then not Named_Fact_Equals
                (Declaration.Facts,
                 Model.Digits_Fact,
                 Declaration.Digits_Constraint.Static_Value)
            then
               Add
                 (Invalid_Fact,
                  "/declarations/" & ID & "/shape/digits",
                  "digits fact contradicts digits constraint");
            end if;
            if Declaration.Kind in
              Model.Ordinary_Fixed_Point | Model.Decimal_Fixed_Point
            then
               if not Named_Fact_Equals
                 (Declaration.Facts,
                  Model.Delta_Fact,
                  Declaration.Delta_Constraint.Static_Value)
               then
                  Add
                    (Invalid_Fact,
                     "/declarations/" & ID & "/shape/delta",
                     "delta fact contradicts delta constraint");
               end if;
               if not Named_Fact_Equals
                 (Declaration.Facts,
                  Model.Small_Fact,
                  Declaration.Delta_Constraint.Secondary_Value)
               then
                  Add
                    (Invalid_Fact,
                     "/declarations/" & ID & "/shape/small",
                     "small fact contradicts delta constraint");
               end if;
            end if;
            if Declaration.Kind in Model.Floating_Point
              | Model.Decimal_Fixed_Point
            then
               if Declaration.Digits_Constraint.Kind /= Model.Digits_Constraint
                 or else Declaration.Digits_Constraint.Provenance
                   not in Model.Declared_Subtype | Model.Inherited_From_Base
               then
                  Add
                    (Invalid_Fact,
                     "/declarations/" & ID & "/shape/digits_constraint",
                     "floating/decimal digits require exact declared or inherited provenance");
               end if;
            elsif Declaration.Digits_Constraint.Kind /= Model.Unconstrained then
               Add (Invalid_Fact, "/declarations/" & ID & "/shape/digits_constraint", "inactive digits constraint");
            end if;
            if Declaration.Kind in Model.Ordinary_Fixed_Point
              | Model.Decimal_Fixed_Point
            then
               if Declaration.Delta_Constraint.Kind /= Model.Delta_Constraint
                 or else Declaration.Delta_Constraint.Provenance
                   not in Model.Declared_Subtype | Model.Inherited_From_Base
               then
                  Add (Invalid_Fact, "/declarations/" & ID & "/shape/delta_constraint", "fixed delta requires exact declared or inherited provenance");
               end if;
            elsif Declaration.Delta_Constraint.Kind /= Model.Unconstrained then
               Add (Invalid_Fact, "/declarations/" & ID & "/shape/delta_constraint", "inactive delta constraint");
            end if;
            case Declaration.Kind is
               when Model.Signed_Integer | Model.Modular_Integer
                  | Model.Enumeration | Model.Floating_Point
                  | Model.Ordinary_Fixed_Point | Model.Decimal_Fixed_Point
                  | Model.Boolean_Type | Model.Character_Type =>
                  if Declaration.Constraint.Kind
                    /= Model.Scalar_Range_Constraint
                  then
                     Add (Missing_Mandatory_Fact, "/declarations/" & ID & "/constraint", "concrete scalar requires an explicit effective range fact");
                  end if;
               when Model.Record_Type =>
                  if Declaration.Constraint.Kind
                    not in Model.Unconstrained | Model.Discriminant_Constraint
                  then
                     Add (Invalid_Fact, "/declarations/" & ID & "/constraint", "record declaration accepts only a discriminant constraint");
                  end if;
               when others =>
                  if Declaration.Constraint.Kind /= Model.Unconstrained then
                     Add (Invalid_Fact, "/declarations/" & ID & "/constraint", "this declaration kind has no serialized top-level constraint");
                  end if;
            end case;
            if Declaration.Constraint.Kind = Model.Scalar_Range_Constraint then
               declare
                  Self_Ref : constant Model.Type_Reference :=
                    (Declaration_ID     => Declaration.Stable_ID,
                     Use_Site_Constraint => null);
               begin
                  Check_Known_Value_Against_Type
                    (Declaration.Constraint.Static_Low,
                     Self_Ref,
                     "/declarations/" & ID & "/constraint/static_low");
                  Check_Known_Value_Against_Type
                    (Declaration.Constraint.Static_High,
                     Self_Ref,
                     "/declarations/" & ID & "/constraint/static_high");
               end;
            end if;
            if Declaration.Constraint.Kind /= Model.Unconstrained
              and then Declaration.Constraint.Provenance
                not in Model.Declared_Subtype | Model.Inherited_From_Base
            then
               Add
                 (Invalid_Fact,
                  "/declarations/" & ID & "/constraint/provenance",
                  "declaration constraints must be declared or inherited, never use-site");
            end if;
            if Declaration.Form in
              Model.Subtype_Declaration_Form | Model.Derived_Declaration_Form
            then
               Check_Type_Reference
                 (Declaration.Base_Subtype,
                  "/declarations/" & ID & "/base_subtype");
            end if;
            if Declaration.Kind = Model.Array_Type then
               if Declaration.Array_Rank = 0
                 or else Declaration.Array_Rank
                   /= Natural (Declaration.Array_Dimensions.Length)
               then
                  Add (Invalid_Fact, "/declarations/" & ID & "/shape", "array rank and dimensions disagree");
               end if;
               Check_Type_Reference
                 (Declaration.Array_Component,
                  "/declarations/" & ID & "/shape/component_type");
               Check_Contained_Risk
                 (Declaration,
                  Declaration.Array_Component,
                  "/declarations/" & ID & "/shape/component_type");
               if Has_Known_Fact
                 (Declaration.Facts, Model.Constrained_Fact)
                 and then Has_Known_Fact
                   (Declaration.Facts, Model.Definite_Fact)
                 and then Known_Boolean_Equals
                   (Declaration.Facts, Model.Constrained_Fact, True)
                   /= Known_Boolean_Equals
                     (Declaration.Facts, Model.Definite_Fact, True)
               then
                  Add (Invalid_Fact, "/declarations/" & ID, "array constrainedness and definiteness disagree");
               end if;
               declare
                  Constrained_Dimensions : Natural := 0;
               begin
                  for Dimension of Declaration.Array_Dimensions loop
                     if Dimension.Constraint.Kind /= Model.Unconstrained then
                        Constrained_Dimensions := Constrained_Dimensions + 1;
                     end if;
                  end loop;
                  if Known_Boolean_Equals
                    (Declaration.Facts, Model.Constrained_Fact, True)
                    and then Constrained_Dimensions
                      /= Natural (Declaration.Array_Dimensions.Length)
                  then
                     Add
                       (Invalid_Fact,
                        "/declarations/" & ID & "/shape/constrained",
                        "constrained array requires a constraint on every dimension");
                  elsif Known_Boolean_Equals
                    (Declaration.Facts, Model.Constrained_Fact, False)
                    and then Constrained_Dimensions /= 0
                  then
                     Add
                       (Invalid_Fact,
                        "/declarations/" & ID & "/shape/constrained",
                        "unconstrained array cannot carry constrained dimensions");
                  end if;
               end;
               for Index in Declaration.Array_Dimensions.First_Index
                 .. Declaration.Array_Dimensions.Last_Index
               loop
                  declare
                     Dimension : constant Model.Array_Dimension :=
                       Declaration.Array_Dimensions (Index);
                  begin
                     if Dimension.Position /= Index + 1 then
                        Add
                          (Duplicate_Declaration_Order,
                           "/declarations/" & ID & "/shape/dimensions",
                           "array dimension positions must be dense from one");
                     end if;
                     if Dimension.Next /= null then
                        Add
                          (Invalid_Fact,
                           "/declarations/" & ID & "/shape/dimensions",
                           "vector dimensions cannot carry linked-list payload");
                     end if;
                     Check_Array_Dimension
                       (Dimension,
                        "/declarations/" & ID & "/shape/dimensions");
                     if Dimension.Constraint.Kind /= Model.Unconstrained
                       and then Dimension.Constraint.Provenance
                         not in Model.Declared_Subtype | Model.Inherited_From_Base
                     then
                        Add
                          (Invalid_Fact,
                           "/declarations/" & ID & "/shape/index_constraint/provenance",
                           "declared array index constraints cannot have use-site provenance");
                     end if;
                  end;
               end loop;
            elsif Declaration.Kind = Model.Access_Type then
               Check_Type_Reference
                 (Declaration.Designated_Subtype,
                  "/declarations/" & ID & "/shape/designated_subtype");
            elsif Declaration.Kind = Model.Record_Type then
               for Component of Document.Components loop
                  if Model.Image (Component.Owner_ID) = ID then
                     Check_Contained_Risk
                       (Declaration,
                        Component.Component_Type,
                        "/declarations/" & ID & "/components");
                  end if;
               end loop;
               for Discriminant of Document.Discriminants loop
                  if Model.Image (Discriminant.Owner_ID) = ID then
                     Check_Contained_Risk
                       (Declaration,
                        Discriminant.Discriminant_Type,
                        "/declarations/" & ID & "/discriminants");
                  end if;
               end loop;
            end if;
            if Declaration.Kind /= Model.Array_Type
              and then
                (Declaration.Array_Rank /= 0
                 or else not Declaration.Array_Dimensions.Is_Empty
                 or else Model.US.Length
                   (Declaration.Array_Component.Declaration_ID) /= 0
                 or else Declaration.Array_Component.Use_Site_Constraint /= null)
            then
               Add (Invalid_Fact, "/declarations/" & ID & "/shape", "non-array declaration carries inactive array payload");
            end if;
            if Declaration.Kind /= Model.Access_Type
              and then
                (Model.US.Length
                   (Declaration.Designated_Subtype.Declaration_ID) /= 0
                 or else Declaration.Designated_Subtype.Use_Site_Constraint /= null)
            then
               Add (Invalid_Fact, "/declarations/" & ID & "/shape", "non-access declaration carries inactive designated-type payload");
            end if;
         end;
      end loop;

      for Component of Document.Components loop
         declare
            ID          : constant String := Model.Image (Component.Stable_ID);
            Owner_Count : Natural := 0;
            Same_Order  : Natural := 0;
         begin
            for Candidate of Document.Components loop
               if Model.Image (Candidate.Owner_ID)
                 = Model.Image (Component.Owner_ID)
               then
                  Owner_Count := Owner_Count + 1;
                  if Candidate.Declaration_Order
                    = Component.Declaration_Order
                  then
                     Same_Order := Same_Order + 1;
                  end if;
               end if;
            end loop;
            if Component.Declaration_Order >= Owner_Count
              or else Same_Order /= 1
            then
               Add (Duplicate_Declaration_Order, "/components/" & ID, "component order must be dense and unique per owner");
            end if;
            Check_ID (ID, "/components/" & ID & "/stable_id");
            if ID /= Expected_Named_Child_ID
              (Model.Image (Component.Owner_ID),
               Model.Image (Component.Canonical_Name))
            then
               Add
                 (Invalid_Semantic_ID,
                  "/components/" & ID & "/stable_id",
                  "component ID must encode its owner and canonical name");
            end if;
            if not Is_Canonical_Segment
              (Model.Image (Component.Canonical_Name))
            then
               Add (Invalid_Semantic_ID, "/components/" & ID & "/canonical_name", "component canonical name is malformed");
            end if;
            if not Declaration_Exists (Model.Image (Component.Owner_ID)) then
               Add (Unresolved_Reference, "/components/" & ID & "/owner_id", "component owner does not resolve");
            else
               for Owner of Document.Declarations loop
                  if Model.Image (Owner.Stable_ID)
                    = Model.Image (Component.Owner_ID)
                    and then Owner.Kind /= Model.Record_Type
                  then
                     Add (Invalid_Fact, "/components/" & ID & "/owner_id", "component owner must be a record declaration");
                  end if;
               end loop;
            end if;
            Check_Type_Reference (Component.Component_Type, "/components/" & ID & "/type");
            Check_Facts (Component.Facts, "/components/" & ID);
            for Fact of Component.Facts loop
               if Fact.Name not in Model.Aliased_Fact | Model.Constant_Fact then
                  Add
                    (Invalid_Fact,
                     "/components/" & ID & "/facts/"
                       & Model.Fact_Key (Fact.Name),
                     "component facts are limited to aliased and constant");
               end if;
            end loop;
            if not Has_Compatible_Fact
              (Component.Facts, Model.Aliased_Fact)
              or else not Has_Compatible_Fact
                (Component.Facts, Model.Constant_Fact)
            then
               Add
                 (Missing_Mandatory_Fact,
                  "/components/" & ID,
                  "structural model requires aliased and constant fact slots");
            end if;
            if Profile = Strict_Consumer
              and then
                (not Has_Known_Fact (Component.Facts, Model.Aliased_Fact)
                 or else not Has_Known_Fact
                   (Component.Facts, Model.Constant_Fact))
            then
               Add
                 (Missing_Mandatory_Fact,
                  "/components/" & ID,
                  "strict profile requires Known aliased and constant facts");
            end if;
            if Component.Default_Present then
               if Model.US.Length (Component.Default_Syntax) = 0 then
                  Add (Invalid_Fact, "/components/" & ID & "/default/syntax", "present default syntax must be nonempty");
               end if;
               Check_Expression
                 (Component.Default_Expression,
                  "/components/" & ID & "/default/expression");
               if not Model.Is_Compatible
                 (Model.Constraint_Staticness_Fact,
                  Component.Default_Staticness)
               then
                  Add (Invalid_Fact, "/components/" & ID & "/default", "component default staticness is malformed");
               elsif Profile = Strict_Consumer
                 and then Component.Default_Staticness.Status /= Model.Known
               then
                  Add (Imprecise_Mandatory_Fact, "/components/" & ID & "/default", "component default staticness must be exact");
               elsif Component.Default_Staticness.Status = Model.Known
                 and then Component.Default_Staticness.Value.Boolean_Data
                   /= Component.Default_Static_Value_Present
               then
                  Add (Invalid_Fact, "/components/" & ID & "/default", "static value presence must agree with staticness");
               end if;
               if Component.Default_Static_Value_Present then
                  if not Model.Is_Well_Formed (Component.Default_Value) then
                     Add (Invalid_Fact, "/components/" & ID & "/default", "component static default value is malformed");
                  elsif Profile = Strict_Consumer
                    and then Component.Default_Value.Status /= Model.Known
                  then
                     Add (Imprecise_Mandatory_Fact, "/components/" & ID & "/default", "static component default must be exact");
                  end if;
                  Check_Known_Value_Against_Type
                    (Component.Default_Value,
                     Component.Component_Type,
                     "/components/" & ID & "/default/static_value");
                  Check_Direct_Literal_Agreement
                    (Component.Default_Expression,
                     Component.Default_Value,
                     "/components/" & ID & "/default/static_value");
               end if;
            elsif Component.Default_Expression /= null
              or else Component.Default_Static_Value_Present
              or else Model.US.Length (Component.Default_Syntax) /= 0
              or else not Is_Empty_Fact (Component.Default_Staticness)
              or else not Is_Empty_Fact (Component.Default_Value)
            then
               Add (Invalid_Fact, "/components/" & ID & "/default", "absent default carries inactive payload");
            end if;
            for Path_Index in Component.Variant_Path.First_Index
              .. Component.Variant_Path.Last_Index
            loop
               declare
                  Alternative_ID : constant String :=
                    Component.Variant_Path (Path_Index);
                  Found : Boolean := False;
                  Listed : Boolean := False;
                  Coherent : Boolean := False;
                  Duplicate : Boolean := False;
               begin
                  if Path_Index > Component.Variant_Path.First_Index then
                     for Earlier in Component.Variant_Path.First_Index
                       .. Path_Index - 1
                     loop
                        Duplicate := Duplicate
                          or else Component.Variant_Path (Earlier)
                            = Alternative_ID;
                     end loop;
                  end if;
                  for Part of Document.Variants loop
                     for Alternative of Part.Alternatives loop
                        if Model.Image (Alternative.Stable_ID) = Alternative_ID then
                           Found := True;
                           for Listed_ID of Alternative.Component_IDs loop
                              Listed := Listed or else Listed_ID = ID;
                           end loop;
                           if Path_Index = Component.Variant_Path.First_Index then
                              Coherent :=
                                Model.US.Length
                                  (Part.Parent_Alternative_ID) = 0;
                           else
                              Coherent :=
                                Model.Image (Part.Parent_Alternative_ID)
                                  = Component.Variant_Path (Path_Index - 1);
                           end if;
                           Coherent := Coherent
                             and then Model.Image (Part.Owner_ID)
                               = Model.Image (Component.Owner_ID);
                        end if;
                     end loop;
                  end loop;
                  if not Found then
                     Add (Unresolved_Reference, "/components/" & ID & "/variant_path", "variant alternative does not resolve");
                  elsif not Listed then
                     Add (Invalid_Variant, "/components/" & ID & "/variant_path", "alternative does not list this component");
                  elsif Duplicate or else not Coherent then
                     Add
                       (Invalid_Variant,
                        "/components/" & ID & "/variant_path",
                        "variant path must be an exact ordered ancestor chain without duplicates");
                  end if;
               end;
            end loop;
         end;
      end loop;

      for Discriminant of Document.Discriminants loop
         declare
            ID          : constant String := Model.Image (Discriminant.Stable_ID);
            Owner_Count : Natural := 0;
            Same_Order  : Natural := 0;
         begin
            for Candidate of Document.Discriminants loop
               if Model.Image (Candidate.Owner_ID)
                 = Model.Image (Discriminant.Owner_ID)
               then
                  Owner_Count := Owner_Count + 1;
                  if Candidate.Declaration_Order
                    = Discriminant.Declaration_Order
                  then
                     Same_Order := Same_Order + 1;
                  end if;
               end if;
            end loop;
            if Discriminant.Declaration_Order >= Owner_Count
              or else Same_Order /= 1
            then
               Add (Duplicate_Declaration_Order, "/discriminants/" & ID, "discriminant order must be dense and unique per owner");
            end if;
            Check_ID (ID, "/discriminants/" & ID & "/stable_id");
            if ID /= Expected_Named_Child_ID
              (Model.Image (Discriminant.Owner_ID),
               Model.Image (Discriminant.Canonical_Name))
            then
               Add
                 (Invalid_Semantic_ID,
                  "/discriminants/" & ID & "/stable_id",
                  "discriminant ID must encode its owner and canonical name");
            end if;
            if not Is_Canonical_Segment
              (Model.Image (Discriminant.Canonical_Name))
            then
               Add (Invalid_Semantic_ID, "/discriminants/" & ID & "/canonical_name", "discriminant canonical name is malformed");
            end if;
            if not Declaration_Exists (Model.Image (Discriminant.Owner_ID)) then
               Add (Unresolved_Reference, "/discriminants/" & ID & "/owner_id", "discriminant owner does not resolve");
            else
               for Owner of Document.Declarations loop
                  if Model.Image (Owner.Stable_ID)
                    = Model.Image (Discriminant.Owner_ID)
                    and then Owner.Kind /= Model.Record_Type
                  then
                     Add (Invalid_Fact, "/discriminants/" & ID & "/owner_id", "discriminant owner must be a record declaration");
                  end if;
               end loop;
            end if;
            Check_Type_Reference (Discriminant.Discriminant_Type, "/discriminants/" & ID & "/type");
            if not Model.Is_Compatible
              (Model.Aliased_Fact, Discriminant.Aliased_Flag)
              or else not Model.Is_Compatible
                (Model.Constant_Fact, Discriminant.Constant_Flag)
            then
               Add
                 (Invalid_Fact,
                  "/discriminants/" & ID,
                  "discriminant aliased and constant facts are malformed");
            elsif Profile = Strict_Consumer
              and then
                (Discriminant.Aliased_Flag.Status /= Model.Known
                 or else Discriminant.Constant_Flag.Status /= Model.Known)
            then
               Add
                 (Missing_Mandatory_Fact,
                  "/discriminants/" & ID,
                  "strict profile requires Known aliased and constant facts");
            end if;
            if Discriminant.Default_Present
            then
               if Model.US.Length (Discriminant.Default_Syntax) = 0 then
                  Add (Invalid_Fact, "/discriminants/" & ID & "/default/syntax", "present default syntax must be nonempty");
               end if;
               Check_Expression
                 (Discriminant.Default_Expression,
                  "/discriminants/" & ID & "/default/expression");
               if not Model.Is_Compatible
                 (Model.Constraint_Staticness_Fact,
                  Discriminant.Default_Staticness)
               then
                  Add (Invalid_Fact, "/discriminants/" & ID & "/default", "discriminant default staticness is malformed");
               elsif Profile = Strict_Consumer
                 and then Discriminant.Default_Staticness.Status /= Model.Known
               then
                  Add (Imprecise_Mandatory_Fact, "/discriminants/" & ID & "/default", "discriminant default staticness must be exact");
               elsif Discriminant.Default_Staticness.Status = Model.Known
                 and then Discriminant.Default_Staticness.Value.Boolean_Data
                   /= Discriminant.Default_Static_Value_Present
               then
                  Add (Invalid_Fact, "/discriminants/" & ID & "/default", "static value presence must agree with staticness");
               end if;
               if Discriminant.Default_Static_Value_Present then
                  if not Model.Is_Well_Formed (Discriminant.Default_Value) then
                     Add (Invalid_Fact, "/discriminants/" & ID & "/default", "discriminant static default value is malformed");
                  elsif Profile = Strict_Consumer
                    and then Discriminant.Default_Value.Status /= Model.Known
                  then
                     Add (Imprecise_Mandatory_Fact, "/discriminants/" & ID & "/default", "static discriminant default must be exact");
                  end if;
                  Check_Known_Value_Against_Type
                    (Discriminant.Default_Value,
                     Discriminant.Discriminant_Type,
                     "/discriminants/" & ID & "/default/static_value");
                  Check_Direct_Literal_Agreement
                    (Discriminant.Default_Expression,
                     Discriminant.Default_Value,
                     "/discriminants/" & ID & "/default/static_value");
               end if;
            elsif Discriminant.Default_Expression /= null
              or else Discriminant.Default_Static_Value_Present
              or else Model.US.Length (Discriminant.Default_Syntax) /= 0
              or else not Is_Empty_Fact (Discriminant.Default_Staticness)
              or else not Is_Empty_Fact (Discriminant.Default_Value)
            then
               Add (Invalid_Fact, "/discriminants/" & ID & "/default", "absent default carries inactive payload");
            end if;
         end;
      end loop;

      for Item of Document.Entities loop
         Check_ID
           (Model.Image (Item.Stable_ID),
            "/entities/" & Model.Image (Item.Stable_ID) & "/stable_id");
         if Model.Image (Item.Stable_ID) /= Expected_Entity_ID (Item) then
            Add
              (Invalid_Semantic_ID,
               "/entities/" & Model.Image (Item.Stable_ID) & "/stable_id",
               "entity ID must exactly encode canonical name and enclosing generic bindings");
         end if;
         if Model.US.Length (Item.Entity_Type.Declaration_ID) > 0 then
            Check_Type_Reference (Item.Entity_Type, "/entities/type");
         end if;
         if not Model.Is_Canonical_Name (Model.Image (Item.Canonical_Name)) then
            Add
              (Invalid_Semantic_ID,
               "/entities/canonical_name",
               "entity canonical names must use normalized Ada segments");
         end if;
         declare
            Is_Callable : constant Boolean :=
              Item.Kind = Model.Subprogram_Entity
              or else
                (Item.Kind = Model.Generic_Formal_Entity
                 and then Item.Formal_Kind = Model.Subprogram_Actual);
            Expected_Position : Natural := 0;
            Is_Object_Formal : constant Boolean :=
              Item.Kind = Model.Generic_Formal_Entity
              and then Item.Formal_Kind = Model.Object_Actual;
            Is_Typed_Entity : constant Boolean :=
              Item.Kind = Model.Object_Entity
              or else
                (Item.Kind = Model.Generic_Formal_Entity
                 and then Item.Formal_Kind = Model.Object_Actual);
            Is_Package_Formal : constant Boolean :=
              Item.Kind = Model.Generic_Formal_Entity
              and then Item.Formal_Kind = Model.Package_Actual;
            Is_Type_Formal : constant Boolean :=
              Item.Kind = Model.Generic_Formal_Entity
              and then Item.Formal_Kind = Model.Type_Actual;
         begin
            if Is_Typed_Entity
              /= (Model.US.Length (Item.Entity_Type.Declaration_ID) > 0)
            then
               Add
                 (Missing_Mandatory_Fact,
                  "/entities/type",
                  "object/value entities require exactly one resolved type");
            end if;
            if Is_Callable /= Item.Callable_Profile_Present then
               Add
                 (Missing_Mandatory_Fact,
                  "/entities/callable_profile",
                  "subprogram entities and formals require exactly one callable profile");
            end if;
            if Item.Callable_Profile_Present then
               for Parameter of Item.Parameters loop
                  if Parameter.Position /= Expected_Position then
                     Add
                       (Duplicate_Declaration_Order,
                        "/entities/callable_profile/parameters",
                        "callable parameter positions must be dense and canonical");
                  end if;
                  Expected_Position := Expected_Position + 1;
                  if not Is_Canonical_Segment
                    (Model.Image (Parameter.Canonical_Name))
                  then
                     Add
                       (Invalid_Semantic_ID,
                        "/entities/callable_profile/parameters/canonical_name",
                        "callable parameter canonical name must be one segment");
                  end if;
                  Check_Type_Reference
                    (Parameter.Parameter_Type,
                     "/entities/callable_profile/parameters/type");
                  if Parameter.Parameter_Type.Use_Site_Constraint /= null
                    and then Parameter.Parameter_Type.Use_Site_Constraint.Kind
                      /= Model.Unconstrained
                  then
                     Add
                       (Invalid_Fact,
                        "/entities/callable_profile/parameters/type",
                        "v1 callable parameter types must be unconstrained graph refs");
                  end if;
               end loop;
               if Item.Result_Present then
                  Check_Type_Reference
                    (Item.Result_Type, "/entities/callable_profile/result");
                  if Item.Result_Type.Use_Site_Constraint /= null
                    and then Item.Result_Type.Use_Site_Constraint.Kind
                      /= Model.Unconstrained
                  then
                     Add
                       (Invalid_Fact,
                        "/entities/callable_profile/result",
                        "v1 callable result must be an unconstrained graph ref");
                  end if;
               elsif Model.US.Length (Item.Result_Type.Declaration_ID) /= 0
                 or else Item.Result_Type.Use_Site_Constraint /= null
               then
                  Add
                    (Invalid_Fact,
                     "/entities/callable_profile/result",
                     "procedure profile carries an inactive result payload");
               end if;
            elsif not Item.Parameters.Is_Empty
              or else Item.Result_Present
              or else Model.US.Length (Item.Result_Type.Declaration_ID) /= 0
              or else Item.Result_Type.Use_Site_Constraint /= null
            then
               Add
                 (Invalid_Fact,
                  "/entities/callable_profile",
                  "non-callable entity carries an inactive callable profile");
            end if;
            if Is_Object_Formal /= Item.Object_Mode_Present
              or else
                (Item.Object_Mode_Present
                 and then Item.Object_Mode
                   not in Model.In_Parameter | Model.In_Out_Parameter)
            then
               Add
                 (Missing_Mandatory_Fact,
                  "/entities/object_mode",
                  "generic object formals require an in or in_out mode");
            end if;
            if Is_Package_Formal
              /= (Model.US.Length (Item.Formal_Template_ID) > 0)
            then
               Add
                 (Missing_Mandatory_Fact,
                  "/entities/formal_template_id",
                  "generic package formals require exactly one template edge");
            elsif Is_Package_Formal
              and then not Entity_Has_Kind
                (Model.Image (Item.Formal_Template_ID),
                 Model.Generic_Template_Entity)
            then
               Add
                 (Unresolved_Reference,
                  "/entities/formal_template_id",
                  "generic package formal template does not resolve");
            end if;
            if Is_Package_Formal
              /= Item.Formal_Package_Contract_Present
            then
               Add
                 (Missing_Mandatory_Fact,
                  "/entities/formal_package_contract",
                  "v1 generic package formals require the box-only contract");
            end if;
            if Is_Type_Formal /= Item.Formal_Type_Contract_Present then
               Add
                 (Missing_Mandatory_Fact,
                  "/entities/formal_type_contract",
                  "generic type formals require exactly one closed type contract");
            end if;
         end;
         if Item.Kind = Model.Generic_Formal_Entity then
            declare
               Owner_Count : Natural := 0;
               Same_Order  : Natural := 0;
            begin
               if Item.Formal_Kind = Model.Value_Actual then
                  Add
                    (Invalid_Fact,
                     "/entities/formal_kind",
                     "Ada value actuals bind object formals; value is not a formal kind");
               end if;
               for Candidate of Document.Entities loop
                  if Candidate.Kind = Model.Generic_Formal_Entity
                    and then Model.Image (Candidate.Owner_ID)
                      = Model.Image (Item.Owner_ID)
                  then
                     Owner_Count := Owner_Count + 1;
                     if Candidate.Declaration_Order = Item.Declaration_Order then
                        Same_Order := Same_Order + 1;
                     end if;
                  end if;
               end loop;
               if Item.Declaration_Order >= Owner_Count or else Same_Order /= 1 then
                  Add
                    (Duplicate_Declaration_Order,
                     "/entities/declaration_order",
                     "generic formal order must be dense and unique per template");
               end if;
            end;
            if not Entity_Has_Kind
              (Model.Image (Item.Owner_ID), Model.Generic_Template_Entity)
            then
               Add
                 (Unresolved_Reference,
                  "/entities/owner_id",
                  "generic formal owner must resolve to a generic template");
            end if;
            if not Is_Name_Child
              (Model.Image (Item.Canonical_Name),
               Entity_Canonical_Name (Model.Image (Item.Owner_ID)))
            then
               Add
                 (Invalid_Semantic_ID,
                  "/entities/canonical_name",
                  "generic formal canonical name must be inside its template");
            end if;
            if Item.Formal_Kind = Model.Object_Actual
              and then Model.US.Length (Item.Entity_Type.Declaration_ID) = 0
            then
               Add
                 (Missing_Mandatory_Fact,
                  "/entities/type",
                  "object generic formals require a resolved type");
            end if;
         elsif Model.US.Length (Item.Owner_ID) > 0
           and then not Any_ID_Exists (Model.Image (Item.Owner_ID))
         then
            Add
              (Unresolved_Reference,
               "/entities/owner_id",
               "entity owner does not resolve");
         end if;
         if Item.Kind /= Model.Generic_Formal_Entity then
            declare
               Expected_Owner : Model.Text;
               Longest        : Natural := 0;
            begin
               for Candidate of Document.Entities loop
                  if Candidate.Kind = Model.Package_Entity
                    and then Model.Image (Candidate.Stable_ID)
                      /= Model.Image (Item.Stable_ID)
                    and then Is_Name_Child
                      (Model.Image (Item.Canonical_Name),
                       Model.Image (Candidate.Canonical_Name))
                    and then Model.US.Length (Candidate.Canonical_Name) > Longest
                  then
                     Longest := Model.US.Length (Candidate.Canonical_Name);
                     Expected_Owner := Candidate.Stable_ID;
                  end if;
               end loop;
               if Model.Image (Item.Owner_ID) /= Model.Image (Expected_Owner) then
                  Add
                    (Invalid_Semantic_ID,
                     "/entities/owner_id",
                     "entity owner must be the longest enclosing package instance");
               end if;
            end;
         end if;
         if Model.US.Length (Item.Instantiated_Template_ID) > 0 then
            if Item.Kind /= Model.Package_Entity
              or else not Entity_Has_Kind
                (Model.Image (Item.Instantiated_Template_ID),
                 Model.Generic_Template_Entity)
            then
               Add
                 (Unresolved_Reference,
                  "/entities/instantiated_template_id",
                  "only a package instance may reference a generic template");
            end if;
            for Formal of Document.Entities loop
               if Formal.Kind = Model.Generic_Formal_Entity
                 and then Model.Image (Formal.Owner_ID)
                   = Model.Image (Item.Instantiated_Template_ID)
               then
                  declare
                     Count : Natural := 0;
                  begin
                     for Actual of Document.Generic_Actuals loop
                        if Model.Image (Actual.Instance_ID)
                          = Model.Image (Item.Stable_ID)
                          and then Model.Image (Actual.Formal_ID)
                            = Model.Image (Formal.Stable_ID)
                        then
                           Count := Count + 1;
                        end if;
                     end loop;
                     if Count /= 1 then
                        Add
                          (Missing_Mandatory_Fact,
                           "/entities/instantiated_template_id",
                           "each generic formal requires exactly one typed actual");
                     end if;
                  end;
               end if;
            end loop;
         end if;
      end loop;

      for Item of Document.Enumeration_Literals loop
         declare
            Owner_Count : Natural := 0;
            Same_Order  : Natural := 0;
         begin
            for Candidate of Document.Enumeration_Literals loop
               if Model.Image (Candidate.Owner_ID) = Model.Image (Item.Owner_ID) then
                  Owner_Count := Owner_Count + 1;
                  if Candidate.Declaration_Order = Item.Declaration_Order then
                     Same_Order := Same_Order + 1;
                  end if;
               end if;
            end loop;
            if Item.Declaration_Order >= Owner_Count or else Same_Order /= 1 then
               Add (Duplicate_Declaration_Order, "/enum_literals", "enum order must be dense and unique per owner");
            end if;
         end;
         Check_ID
           (Model.Image (Item.Stable_ID),
            "/enum_literals/" & Model.Image (Item.Stable_ID) & "/stable_id");
         if Model.Image (Item.Stable_ID) /= Expected_Named_Child_ID
           (Model.Image (Item.Owner_ID), Model.Image (Item.Canonical_Name))
         then
            Add
              (Invalid_Semantic_ID,
               "/enum_literals/" & Model.Image (Item.Stable_ID) & "/stable_id",
               "enum literal ID must encode its owner and canonical name");
         end if;
         if not Is_Canonical_Segment (Model.Image (Item.Canonical_Name)) then
            Add (Invalid_Semantic_ID, "/enum_literals/canonical_name", "enum literal canonical name is malformed");
         end if;
         if not Declaration_Exists (Model.Image (Item.Owner_ID)) then
            Add (Unresolved_Reference, "/enum_literals/owner_id", "enum owner does not resolve");
         else
            for Owner of Document.Declarations loop
               if Model.Image (Owner.Stable_ID) = Model.Image (Item.Owner_ID)
                 and then Owner.Kind /= Model.Enumeration
               then
                  Add
                    (Invalid_Fact,
                     "/enum_literals/owner_id",
                     "enum literal owner must be an enumeration declaration");
               end if;
            end loop;
         end if;
         if not Model.Is_Canonical_Decimal (Model.Image (Item.Position)) then
            Add (Invalid_Fact, "/enum_literals/position", "enum position must be a canonical decimal string");
         else
            declare
               Expected : constant String :=
                 Natural'Image (Item.Declaration_Order);
            begin
               if Model.Image (Item.Position)
                 /= Expected (Expected'First + 1 .. Expected'Last)
               then
                  Add
                    (Invalid_Fact,
                     "/enum_literals/position",
                     "enum position must equal semantic declaration order");
               end if;
            end;
         end if;
      end loop;

      for Declaration of Document.Declarations loop
         if Declaration.Kind = Model.Enumeration then
            declare
               Expected : Model.Text_Vectors.Vector;
               Owner_Count : Natural := 0;
               Matches : Boolean := True;
            begin
               for Literal of Document.Enumeration_Literals loop
                  if Model.Image (Literal.Owner_ID)
                    = Model.Image (Declaration.Stable_ID)
                  then
                     Owner_Count := Owner_Count + 1;
                  end if;
               end loop;
               if Owner_Count > 0 then
                  for Position in 0 .. Owner_Count - 1 loop
                     for Literal of Document.Enumeration_Literals loop
                        if Model.Image (Literal.Owner_ID)
                          = Model.Image (Declaration.Stable_ID)
                          and then Literal.Declaration_Order = Position
                        then
                           Expected.Append (Model.Image (Literal.Stable_ID));
                        end if;
                     end loop;
                  end loop;
               end if;
               if Expected.Length /= Declaration.Enum_Literal_IDs.Length then
                  Matches := False;
               elsif not Expected.Is_Empty then
                  for Index in Expected.First_Index .. Expected.Last_Index loop
                     Matches := Matches
                       and then Expected (Index)
                         = Declaration.Enum_Literal_IDs (Index);
                  end loop;
               end if;
               if not Matches then
                  Add
                    (Invalid_Fact,
                     "/declarations/" & Model.Image (Declaration.Stable_ID)
                       & "/shape/literal_ids",
                     "enumeration literal IDs must exactly match owned literals in semantic order");
               end if;
               if Declaration.Form = Model.Type_Declaration_Form then
                  declare
                     Expected_High_Image : constant String :=
                       (if Owner_Count = 0
                        then ""
                        else Natural'Image (Owner_Count - 1));
                     Expected_High : constant String :=
                       (if Owner_Count = 0
                        then ""
                        else Expected_High_Image
                          (Expected_High_Image'First + 1
                           .. Expected_High_Image'Last));
                  begin
                     if Owner_Count = 0
                       or else Declaration.Constraint.Static_Low.Status
                         /= Model.Known
                       or else Declaration.Constraint.Static_High.Status
                         /= Model.Known
                       or else Declaration.Constraint.Static_Low.Value.Kind
                         /= Model.Decimal_Integer_Value
                       or else Declaration.Constraint.Static_High.Value.Kind
                         /= Model.Decimal_Integer_Value
                       or else Model.Image
                         (Declaration.Constraint.Static_Low.Value.Decimal_Data)
                         /= "0"
                       or else Model.Image
                         (Declaration.Constraint.Static_High.Value.Decimal_Data)
                         /= Expected_High
                     then
                        Add
                          (Invalid_Fact,
                           "/declarations/"
                             & Model.Image (Declaration.Stable_ID)
                             & "/shape/range",
                           "base enumeration range must be exactly 0 through N-1");
                     end if;
                  end;
               end if;
            end;
         elsif not Declaration.Enum_Literal_IDs.Is_Empty then
            Add
              (Invalid_Fact,
               "/declarations/" & Model.Image (Declaration.Stable_ID)
                 & "/shape/literal_ids",
               "only enumeration declarations may list enum literals");
         end if;
      end loop;

      for Item of Document.Generic_Actuals loop
         declare
            Owner_Count : Natural := 0;
            Same_Order  : Natural := 0;
         begin
            for Candidate of Document.Generic_Actuals loop
               if Model.Image (Candidate.Instance_ID)
                 = Model.Image (Item.Instance_ID)
               then
                  Owner_Count := Owner_Count + 1;
                  if Candidate.Declaration_Order = Item.Declaration_Order then
                     Same_Order := Same_Order + 1;
                  end if;
               end if;
            end loop;
            if Item.Declaration_Order >= Owner_Count or else Same_Order /= 1 then
               Add (Duplicate_Declaration_Order, "/generic_actuals", "generic actual order must be dense and unique per instance");
            end if;
         end;
         Check_ID
           (Model.Image (Item.Stable_ID),
            "/generic_actuals/" & Model.Image (Item.Stable_ID) & "/stable_id");
         declare
            Identity_Value : constant String := Actual_Identity_Value (Item);
            Expected : constant String :=
              "decl:"
              & Expanded_Canonical_Name
                  (Entity_Canonical_Name (Model.Image (Item.Instance_ID)),
                   Include_Self => False)
              & ".actual."
              & Model.Image (Item.Formal_Canonical_Name)
              & "[value=" & Identity_Value & "]#public";
         begin
            if Identity_Value'Length = 0
              or else Model.Image (Item.Stable_ID) /= Expected
            then
               Add
                 (Invalid_Semantic_ID,
                  "/generic_actuals/" & Model.Image (Item.Stable_ID),
                  "generic actual identity must encode its exact value or resolved declaration");
            end if;
         end;
         if not Entity_Has_Kind
           (Model.Image (Item.Formal_ID), Model.Generic_Formal_Entity)
           or else not Entity_Has_Kind
             (Model.Image (Item.Instance_ID), Model.Package_Entity)
           or else not Entity_Has_Kind
             (Model.Image (Item.Template_ID), Model.Generic_Template_Entity)
         then
            Add
              (Unresolved_Reference,
               "/generic_actuals",
               "generic formal, template, or package instance has the wrong entity kind");
         end if;
         for Formal of Document.Entities loop
            if Model.Image (Formal.Stable_ID) = Model.Image (Item.Formal_ID) then
               if Model.Image (Formal.Owner_ID) /= Model.Image (Item.Template_ID)
                 or else Formal.Declaration_Order /= Item.Declaration_Order
                 or else not
                   ((Formal.Formal_Kind = Model.Object_Actual
                     and then Formal.Object_Mode_Present
                     and then
                       ((Item.Kind = Model.Value_Actual
                         and then Formal.Object_Mode = Model.In_Parameter)
                        or else
                          (Item.Kind = Model.Object_Actual
                           and then Formal.Object_Mode
                             = Model.In_Out_Parameter)))
                    or else
                      (Formal.Formal_Kind /= Model.Object_Actual
                       and then Formal.Formal_Kind = Item.Kind))
                 or else Canonical_Tail
                   (Model.Image (Formal.Canonical_Name))
                     /= Model.Image (Item.Formal_Canonical_Name)
               then
                  Add
                    (Invalid_Fact,
                     "/generic_actuals",
                     "formal must belong to the instantiated template and preserve formal order");
               end if;
               if not Is_Canonical_Segment
                 (Model.Image (Item.Formal_Canonical_Name))
               then
                  Add (Invalid_Semantic_ID, "/generic_actuals/formal_canonical_name", "formal canonical name is malformed");
               end if;
               if Item.Kind in Model.Value_Actual | Model.Object_Actual then
                  Check_Known_Value_Against_Type
                    (Item.Semantic_Value,
                     Formal.Entity_Type,
                     "/generic_actuals/value");
               end if;
               if Item.Kind = Model.Type_Actual then
                  declare
                     Root    : constant String := Root_Type_ID
                       (Model.Image (Item.Type_Value.Declaration_ID));
                     Matches : Boolean := False;
                  begin
                     for Target of Document.Declarations loop
                        if Model.Image (Target.Stable_ID) = Root
                          and then Target.Kind = Model.Signed_Integer
                        then
                           Matches := True;
                        end if;
                     end loop;
                     if Formal.Formal_Type_Contract_Present and then not Matches then
                        Add
                          (Invalid_Fact,
                           "/generic_actuals/value",
                           "generic type actual does not satisfy the formal type contract");
                     end if;
                  end;
               elsif Item.Kind = Model.Object_Actual then
                  for Actual_Object of Document.Entities loop
                     if Model.Image (Actual_Object.Stable_ID)
                       = Model.Image (Item.Declaration_Value)
                       and then Type_Family_Key
                         (Model.Image
                            (Actual_Object.Entity_Type.Declaration_ID))
                         /= Type_Family_Key
                           (Model.Image (Formal.Entity_Type.Declaration_ID))
                     then
                        Add
                          (Invalid_Fact,
                           "/generic_actuals/value_id",
                           "generic object actual type does not conform to its formal");
                     end if;
                  end loop;
               elsif Item.Kind = Model.Subprogram_Actual then
                  for Actual_Subprogram of Document.Entities loop
                     if Model.Image (Actual_Subprogram.Stable_ID)
                       = Model.Image (Item.Declaration_Value)
                     then
                        declare
                           Matches : Boolean :=
                             Actual_Subprogram.Callable_Profile_Present
                             and then Formal.Callable_Profile_Present
                             and then Actual_Subprogram.Parameters.Length
                               = Formal.Parameters.Length
                             and then Actual_Subprogram.Result_Present
                               = Formal.Result_Present;
                        begin
                           if Matches and then not Formal.Parameters.Is_Empty then
                              for Position in Formal.Parameters.First_Index
                                .. Formal.Parameters.Last_Index
                              loop
                                 Matches := Matches
                                   and then Formal.Parameters (Position).Mode
                                     = Actual_Subprogram.Parameters (Position).Mode
                                   and then Type_Family_Key
                                     (Model.Image
                                        (Formal.Parameters (Position)
                                           .Parameter_Type.Declaration_ID))
                                     = Type_Family_Key
                                       (Model.Image
                                          (Actual_Subprogram.Parameters (Position)
                                             .Parameter_Type.Declaration_ID));
                              end loop;
                           end if;
                           if Matches and then Formal.Result_Present then
                              Matches := Type_Family_Key
                                (Model.Image (Formal.Result_Type.Declaration_ID))
                                = Type_Family_Key
                                  (Model.Image
                                     (Actual_Subprogram.Result_Type.Declaration_ID));
                           end if;
                           if not Matches then
                              Add
                                (Invalid_Fact,
                                 "/generic_actuals/value_id",
                                 "generic subprogram actual profile does not conform");
                           end if;
                        end;
                     end if;
                  end loop;
               elsif Item.Kind = Model.Package_Actual then
                  for Actual_Package of Document.Entities loop
                     if Model.Image (Actual_Package.Stable_ID)
                       = Model.Image (Item.Declaration_Value)
                       and then Model.Image
                         (Actual_Package.Instantiated_Template_ID)
                         /= Model.Image (Formal.Formal_Template_ID)
                     then
                        Add
                          (Invalid_Fact,
                           "/generic_actuals/value_id",
                           "generic package actual instantiates the wrong template");
                     end if;
                  end loop;
               end if;
            end if;
         end loop;
         for Instance of Document.Entities loop
            if Model.Image (Instance.Stable_ID) = Model.Image (Item.Instance_ID)
              and then Model.Image (Instance.Instantiated_Template_ID)
                /= Model.Image (Item.Template_ID)
            then
               Add
                 (Invalid_Fact,
                  "/generic_actuals/template_id",
                  "generic actual template must match its instance edge");
            end if;
         end loop;
         case Item.Kind is
            when Model.Type_Actual =>
               Check_Type_Reference (Item.Type_Value, "/generic_actuals/value");
               if not Is_Empty_Fact (Item.Semantic_Value)
                 or else Model.US.Length (Item.Declaration_Value) /= 0
               then
                  Add (Invalid_Fact, "/generic_actuals", "type actual carries inactive value payload");
               end if;
            when Model.Value_Actual =>
               if not Model.Is_Well_Formed (Item.Semantic_Value) then
                  Add (Invalid_Fact, "/generic_actuals/value", "generic value actual is malformed");
               end if;
               if Item.Semantic_Value.Status /= Model.Known then
                  Add
                    (Imprecise_Mandatory_Fact,
                     "/generic_actuals/value",
                     "generic value actual must be exact before it can enter stable identity");
               end if;
               if Model.US.Length (Item.Type_Value.Declaration_ID) /= 0
                 or else Item.Type_Value.Use_Site_Constraint /= null
                 or else Model.US.Length (Item.Declaration_Value) /= 0
               then
                  Add (Invalid_Fact, "/generic_actuals", "value actual carries inactive type/declaration payload");
               end if;
            when Model.Object_Actual =>
               if not Entity_Has_Kind
                 (Model.Image (Item.Declaration_Value), Model.Object_Entity)
               then
                  Add (Unresolved_Reference, "/generic_actuals/value_id", "generic object actual is unresolved");
               end if;
               if Model.US.Length (Item.Type_Value.Declaration_ID) /= 0
                 or else Item.Type_Value.Use_Site_Constraint /= null
                 or else not Is_Empty_Fact (Item.Semantic_Value)
               then
                  Add (Invalid_Fact, "/generic_actuals", "object actual carries inactive type/value payload");
               end if;
            when Model.Package_Actual | Model.Subprogram_Actual =>
               if (Item.Kind = Model.Package_Actual
                   and then not Entity_Has_Kind
                     (Model.Image (Item.Declaration_Value), Model.Package_Entity))
                 or else
                   (Item.Kind = Model.Subprogram_Actual
                    and then not Entity_Has_Kind
                      (Model.Image (Item.Declaration_Value),
                       Model.Subprogram_Entity))
               then
                  Add (Unresolved_Reference, "/generic_actuals/value_id", "generic declaration actual is unresolved");
               end if;
               if Model.US.Length (Item.Type_Value.Declaration_ID) /= 0
                 or else Item.Type_Value.Use_Site_Constraint /= null
                 or else not Is_Empty_Fact (Item.Semantic_Value)
               then
                  Add (Invalid_Fact, "/generic_actuals", "declaration actual carries inactive type/value payload");
               end if;
         end case;
      end loop;

      if Document.Annotations.Length > 1 then
         for Index in Document.Annotations.First_Index
           .. Document.Annotations.Last_Index - 1
         loop
            declare
               Left  : constant Model.Annotation := Document.Annotations (Index);
               Right : constant Model.Annotation := Document.Annotations (Index + 1);
               Out_Of_Order : constant Boolean :=
                 Model.Image (Left.Target_ID) > Model.Image (Right.Target_ID)
                 or else
                   (Model.Image (Left.Target_ID) = Model.Image (Right.Target_ID)
                    and then
                      (Model.Image (Left.Namespace) > Model.Image (Right.Namespace)
                       or else
                         (Model.Image (Left.Namespace) = Model.Image (Right.Namespace)
                          and then
                            (Model.Image (Left.Action) > Model.Image (Right.Action)
                             or else
                               (Model.Image (Left.Action) = Model.Image (Right.Action)
                                and then Left.Declaration_Order
                                  >= Right.Declaration_Order)))));
            begin
               if Out_Of_Order then
                  Add (Invalid_Fact, "/annotations", "annotations must be in canonical target/namespace/action/order");
               end if;
            end;
         end loop;
      end if;
      for Item of Document.Annotations loop
         declare
            Owner_Count : Natural := 0;
            Same_Order  : Natural := 0;
         begin
            for Candidate of Document.Annotations loop
               if Model.Image (Candidate.Target_ID) = Model.Image (Item.Target_ID) then
                  Owner_Count := Owner_Count + 1;
                  if Candidate.Declaration_Order = Item.Declaration_Order then
                     Same_Order := Same_Order + 1;
                  end if;
               end if;
            end loop;
            if Item.Declaration_Order >= Owner_Count or else Same_Order /= 1 then
               Add (Duplicate_Declaration_Order, "/annotations", "annotation order must be dense and unique per target");
            end if;
         end;
         if not Expression_ID_Exists (Model.Image (Item.Target_ID))
           or else
             (not Declaration_Exists (Model.Image (Item.Target_ID))
              and then not Component_Exists (Model.Image (Item.Target_ID))
              and then not Discriminant_Exists (Model.Image (Item.Target_ID))
              and then not Enumeration_Literal_Exists
                (Model.Image (Item.Target_ID))
              and then not Entity_Has_Kind
                (Model.Image (Item.Target_ID), Model.Object_Entity)
              and then not Entity_Has_Kind
                (Model.Image (Item.Target_ID), Model.Package_Entity)
              and then not Entity_Has_Kind
                (Model.Image (Item.Target_ID), Model.Subprogram_Entity)
              and then not Entity_Has_Kind
                (Model.Image (Item.Target_ID), Model.Generic_Formal_Entity)
              and then not Entity_Has_Kind
                (Model.Image (Item.Target_ID), Model.Generic_Template_Entity))
         then
            Add (Unresolved_Reference, "/annotations/target_id", "annotation target is unresolved");
         end if;
         if not Is_Annotation_Namespace (Model.Image (Item.Namespace))
           or else not Is_Annotation_Action (Model.Image (Item.Action))
         then
            Add (Invalid_Fact, "/annotations", "annotation namespace/action is outside the closed lexical grammar");
         end if;
         if Item.Arguments.Is_Empty
           and then Model.US.Length (Item.Expression_Syntax) = 0
         then
            Add (Missing_Mandatory_Fact, "/annotations", "annotation requires typed arguments or retained expression text");
         end if;
         for Index in Item.Arguments.First_Index .. Item.Arguments.Last_Index loop
            Check_Typed_Value
              (Item.Arguments (Index), "/annotations/arguments");
         end loop;
      end loop;

      for Part of Document.Variants loop
         declare
            ID          : constant String := Model.Image (Part.Stable_ID);
            Others_Seen : Boolean := False;
            Alternative_Position : Natural := 0;
            Previous_Alternative_Key : Model.Text;
            procedure Check_Selector_Value
              (Fact : Model.Semantic_Fact;
               Path : String)
            is
            begin
               for Selector of Document.Discriminants loop
                  if Model.Image (Selector.Stable_ID)
                    = Model.Image (Part.Selector_Discriminant_ID)
                  then
                     Check_Known_Value_Against_Type
                       (Fact, Selector.Discriminant_Type, Path);
                  end if;
               end loop;
            end Check_Selector_Value;
            function Selector_Kind_Matches
              (Kind : Model.Type_Kind) return Boolean
            is
            begin
               for Selector of Document.Discriminants loop
                  if Model.Image (Selector.Stable_ID)
                    = Model.Image (Part.Selector_Discriminant_ID)
                  then
                     for Declaration of Document.Declarations loop
                        if Model.Image (Declaration.Stable_ID)
                          = Model.Image
                            (Selector.Discriminant_Type.Declaration_ID)
                        then
                           return Declaration.Kind = Kind;
                        end if;
                     end loop;
                  end if;
               end loop;
               return False;
            end Selector_Kind_Matches;
            function Selector_Root_ID return String is
            begin
               for Selector of Document.Discriminants loop
                  if Model.Image (Selector.Stable_ID)
                    = Model.Image (Part.Selector_Discriminant_ID)
                  then
                     return Root_Type_ID
                       (Model.Image
                          (Selector.Discriminant_Type.Declaration_ID));
                  end if;
               end loop;
               return "";
            end Selector_Root_ID;
            function Name_Choice_Type_Family (Target_ID : String) return String is
            begin
               for Entity of Document.Entities loop
                  if Model.Image (Entity.Stable_ID) = Target_ID
                    and then
                      (Entity.Kind = Model.Object_Entity
                       or else
                         (Entity.Kind = Model.Generic_Formal_Entity
                          and then Entity.Formal_Kind = Model.Object_Actual))
                  then
                     return Type_Family_Key
                       (Model.Image (Entity.Entity_Type.Declaration_ID));
                  end if;
               end loop;
               for Literal of Document.Enumeration_Literals loop
                  if Model.Image (Literal.Stable_ID) = Target_ID then
                     return Type_Family_Key (Model.Image (Literal.Owner_ID));
                  end if;
               end loop;
               return "";
            end Name_Choice_Type_Family;
            function Enum_Position_Contradicts
              (Target_ID : String;
               Fact      : Model.Semantic_Fact) return Boolean
            is
            begin
               for Literal of Document.Enumeration_Literals loop
                  if Model.Image (Literal.Stable_ID) = Target_ID then
                     return
                       Fact.Status = Model.Known
                       and then
                         (Fact.Value.Kind /= Model.Decimal_Integer_Value
                          or else Model.Image (Fact.Value.Decimal_Data)
                            /= Model.Image (Literal.Position));
                  end if;
               end loop;
               return False;
            end Enum_Position_Contradicts;
         begin
            Check_ID (ID, "/variants/" & ID & "/stable_id");
            if Part.Alternatives.Is_Empty then
               Add (Invalid_Variant, "/variants/" & ID, "variant part requires at least one alternative");
            end if;
            if Model.US.Length (Part.Parent_Alternative_ID) = 0 then
               declare
                  Root_Count : Natural := 0;
               begin
                  for Candidate of Document.Variants loop
                     if Model.Image (Candidate.Owner_ID) = Model.Image (Part.Owner_ID)
                       and then Model.US.Length (Candidate.Parent_Alternative_ID) = 0
                     then
                        Root_Count := Root_Count + 1;
                     end if;
                  end loop;
                  if Root_Count /= 1 then
                     Add (Invalid_Variant, "/variants/" & ID, "record owner may have only one root variant part");
                  end if;
               end;
            end if;
            declare
               Prefix_ID : constant String :=
                 (if Model.US.Length (Part.Parent_Alternative_ID) = 0
                  then Model.Image (Part.Owner_ID)
                  else Model.Image (Part.Parent_Alternative_ID));
               Expected : constant String :=
                 Expected_Named_Child_ID
                   (Prefix_ID,
                    "variant."
                    & Selector_Name
                      (Model.Image (Part.Selector_Discriminant_ID)));
            begin
               if ID /= Expected then
                  Add
                    (Invalid_Semantic_ID,
                     "/variants/" & ID & "/stable_id",
                     "variant ID must encode owner path and selector");
               end if;
            end;
            if Model.US.Length (Part.Parent_Alternative_ID) > 0 then
               declare
                  Parent_Found : Boolean := False;
               begin
                  for Candidate of Document.Variants loop
                     for Alternative of Candidate.Alternatives loop
                        if Model.Image (Alternative.Stable_ID)
                          = Model.Image (Part.Parent_Alternative_ID)
                        then
                           Parent_Found := True;
                           if Model.Image (Alternative.Nested_Variant_ID) /= ID
                             or else Model.Image (Candidate.Owner_ID)
                               /= Model.Image (Part.Owner_ID)
                           then
                              Add
                                (Invalid_Variant,
                                 "/variants/" & ID,
                                 "parent alternative must point back to this nested variant with the same owner");
                           end if;
                        end if;
                     end loop;
                  end loop;
                  if not Parent_Found then
                     Add
                       (Unresolved_Reference,
                        "/variants/" & ID & "/parent_alternative_id",
                        "parent alternative does not resolve");
                  end if;
               end;
            end if;
            if not Declaration_Exists (Model.Image (Part.Owner_ID)) then
               Add (Unresolved_Reference, "/variants/" & ID & "/owner_id", "variant owner does not resolve");
            end if;
            if not Discriminant_Exists (Model.Image (Part.Selector_Discriminant_ID)) then
               Add (Unresolved_Reference, "/variants/" & ID & "/selector_discriminant_id", "variant selector does not resolve");
            else
               for Selector of Document.Discriminants loop
                  if Model.Image (Selector.Stable_ID)
                    = Model.Image (Part.Selector_Discriminant_ID)
                    and then Model.Image (Selector.Owner_ID)
                      /= Model.Image (Part.Owner_ID)
                  then
                     Add (Invalid_Variant, "/variants/" & ID, "selector and variant owners differ");
                  end if;
               end loop;
            end if;
            for Alternative of Part.Alternatives loop
               declare
                  Current_Key : constant String := Alternative_Key (Alternative);
               begin
                  if Alternative_Position > 0
                    and then Current_Key <= Model.Image (Previous_Alternative_Key)
                  then
                     Add
                       (Invalid_Variant,
                        "/variants/" & ID & "/alternatives",
                        "alternatives must have unique semantic choice sets in canonical order");
                  end if;
                  Previous_Alternative_Key := Model.To_Text (Current_Key);
               end;
               Check_ID
                 (Model.Image (Alternative.Stable_ID),
                  "/variants/" & ID & "/alternatives/stable_id");
               if Model.Image (Alternative.Stable_ID)
                 /= Expected_Named_Child_ID
                   (ID, "alternative." & Decimal_Image (Alternative_Position))
               then
                  Add
                    (Invalid_Semantic_ID,
                     "/variants/" & ID & "/alternatives/stable_id",
                     "alternative ID must encode canonical choice rank");
               end if;
               if Alternative.Choices.Length = 0 then
                  Add (Invalid_Variant, "/variants/" & ID & "/alternatives", "each alternative requires an exact discrete choice");
               end if;
               if not Is_Sorted_Unique (Alternative.Component_IDs) then
                  Add
                    (Invalid_Variant,
                     "/variants/" & ID & "/alternatives/component_ids",
                     "variant component IDs must be sorted and unique");
               end if;
               if Alternative.Declaration_Order
                 >= Natural (Part.Alternatives.Length)
               then
                  Add (Duplicate_Declaration_Order, "/variants/" & ID, "alternative order must be dense from zero");
               end if;
               for Other of Part.Alternatives loop
                  if Model.Image (Other.Stable_ID)
                    /= Model.Image (Alternative.Stable_ID)
                    and then Other.Declaration_Order
                      = Alternative.Declaration_Order
                  then
                     Add (Duplicate_Declaration_Order, "/variants/" & ID, "alternative order must be unique");
                  end if;
               end loop;
               declare
                  Previous_Choice_Key : Model.Text;
                  Choice_Position     : Natural := 0;
               begin
                  for Choice of Alternative.Choices loop
                     declare
                        Current_Key : constant String := Choice_Key (Choice);
                        Same_Key    : Natural := 0;
                     begin
                        if Choice_Position > 0
                          and then Current_Key <= Model.Image (Previous_Choice_Key)
                        then
                           Add
                             (Invalid_Variant,
                              "/variants/" & ID & "/alternatives/choices",
                              "choices must be unique and in canonical semantic order");
                        end if;
                        for Candidate of Part.Alternatives loop
                           for Other_Choice of Candidate.Choices loop
                              if Choice_Key (Other_Choice) = Current_Key then
                                 Same_Key := Same_Key + 1;
                              end if;
                           end loop;
                        end loop;
                        if Same_Key /= 1 then
                           Add
                             (Invalid_Variant,
                              "/variants/" & ID & "/alternatives/choices",
                              "a semantic variant choice may occur only once");
                        end if;
                        Previous_Choice_Key := Model.To_Text (Current_Key);
                        Choice_Position := Choice_Position + 1;
                     end;
                     case Choice.Kind is
                        when Model.Others_Choice =>
                        if Model.US.Length (Choice.Resolved_ID) /= 0
                          or else not Is_Empty_Type_Reference
                            (Choice.Resolved_Ref)
                          or else Choice.Expression /= null
                          or else Choice.Low /= null
                          or else Choice.High /= null
                          or else not Is_Empty_Fact (Choice.Static_Low)
                          or else not Is_Empty_Fact (Choice.Static_High)
                        then
                           Add (Invalid_Fact, "/variants/choice", "others choice carries inactive payload");
                        end if;
                        if Others_Seen or else Alternative.Choices.Length /= 1 then
                           Add (Invalid_Variant, "/variants/" & ID & "/alternatives", "others must occur once and alone");
                        end if;
                        Others_Seen := True;
                        when Model.Expression_Choice =>
                        if Model.US.Length (Choice.Resolved_ID) /= 0
                          or else not Is_Empty_Type_Reference
                            (Choice.Resolved_Ref)
                          or else Choice.Low /= null
                          or else Choice.High /= null
                          or else not Is_Empty_Fact (Choice.Static_High)
                        then
                           Add (Invalid_Fact, "/variants/choice", "expression choice carries inactive payload");
                        end if;
                        Check_Expression (Choice.Expression, "/variants/choice/expression");
                        if not Model.Is_Well_Formed (Choice.Static_Low) then
                           Add (Invalid_Fact, "/variants/choice/static_value", "literal static value is malformed");
                        elsif Profile = Strict_Consumer
                          and then Choice.Static_Low.Status /= Model.Known
                        then
                           Add (Imprecise_Mandatory_Fact, "/variants/choice/static_value", "expression choice must be exact");
                        end if;
                        Check_Selector_Value
                          (Choice.Static_Low, "/variants/choice/static_value");
                        Check_Direct_Literal_Agreement
                          (Choice.Expression,
                           Choice.Static_Low,
                           "/variants/choice/static_value");
                        when Model.Name_Choice =>
                        if not Is_Empty_Type_Reference (Choice.Resolved_Ref)
                          or else Choice.Expression /= null
                          or else Choice.Low /= null
                          or else Choice.High /= null
                          or else not Is_Empty_Fact (Choice.Static_High)
                        then
                           Add (Invalid_Fact, "/variants/choice", "name choice carries inactive payload");
                        end if;
                        if Name_Choice_Type_Family
                          (Model.Image (Choice.Resolved_ID))'Length = 0
                        then
                           Add
                             (Unresolved_Reference,
                              "/variants/choice/resolved_declaration_id",
                              "name choice must resolve to a value-denoting entity or enum literal");
                        elsif Name_Choice_Type_Family
                          (Model.Image (Choice.Resolved_ID))
                          /= Type_Family_Key (Selector_Root_ID)
                        then
                           Add
                             (Invalid_Fact,
                              "/variants/choice/resolved_declaration_id",
                              "name choice resolved value has the wrong selector type");
                        end if;
                        if not Model.Is_Well_Formed (Choice.Static_Low) then
                           Add (Invalid_Fact, "/variants/choice/static_value", "resolved choice value is malformed");
                        elsif Profile = Strict_Consumer
                          and then Choice.Static_Low.Status /= Model.Known
                        then
                           Add (Imprecise_Mandatory_Fact, "/variants/choice/static_value", "name choice value must be exact");
                        end if;
                        Check_Selector_Value
                          (Choice.Static_Low, "/variants/choice/static_value");
                        if Enum_Position_Contradicts
                          (Model.Image (Choice.Resolved_ID), Choice.Static_Low)
                        then
                           Add
                             (Invalid_Fact,
                              "/variants/choice/static_value",
                              "enum name choice value must equal its literal position");
                        end if;
                        when Model.Subtype_Choice =>
                        if Model.US.Length (Choice.Resolved_ID) /= 0
                          or else Choice.Expression /= null
                          or else Choice.Low /= null
                          or else Choice.High /= null
                        then
                           Add (Invalid_Fact, "/variants/choice", "subtype choice carries inactive payload");
                        end if;
                        Check_Type_Reference (Choice.Resolved_Ref, "/variants/choice/resolved_ref");
                        if not Is_Empty_Fact (Choice.Static_Low)
                          or else not Is_Empty_Fact (Choice.Static_High)
                        then
                           Add (Invalid_Fact, "/variants/choice", "subtype choice carries an inactive singular value");
                        end if;
                        for Subtype_Declaration of Document.Declarations loop
                           if Model.Image (Subtype_Declaration.Stable_ID)
                             = Model.Image (Choice.Resolved_Ref.Declaration_ID)
                           then
                              declare
                                 Effective : Model.Constraint_Access :=
                                   Choice.Resolved_Ref.Use_Site_Constraint;
                              begin
                                 if Effective = null
                                   or else Effective.Kind = Model.Unconstrained
                                 then
                                    Effective :=
                                      Subtype_Declaration.Constraint'Unrestricted_Access;
                                 end if;
                                 if not Selector_Kind_Matches
                                   (Subtype_Declaration.Kind)
                                   or else Type_Family_Key
                                     (Model.Image
                                        (Choice.Resolved_Ref.Declaration_ID))
                                     /= Type_Family_Key (Selector_Root_ID)
                                   or else Effective.Kind
                                     /= Model.Scalar_Range_Constraint
                                   or else Effective.Staticness.Status /= Model.Known
                                   or else not Effective.Staticness.Value.Boolean_Data
                                   or else Effective.Static_Low.Status /= Model.Known
                                   or else Effective.Static_High.Status /= Model.Known
                                 then
                                    Add
                                      (Invalid_Variant,
                                       "/variants/choice/resolved_subtype",
                                       "subtype choice must resolve to one compatible exact static range");
                                 end if;
                              end;
                           end if;
                        end loop;
                        when Model.Range_Choice =>
                        if Model.US.Length (Choice.Resolved_ID) /= 0
                          or else not Is_Empty_Type_Reference
                            (Choice.Resolved_Ref)
                          or else Choice.Expression /= null
                        then
                           Add (Invalid_Fact, "/variants/choice", "range choice carries inactive payload");
                        end if;
                        Check_Expression (Choice.Low, "/variants/choice/low");
                        Check_Expression (Choice.High, "/variants/choice/high");
                        if not Model.Is_Well_Formed (Choice.Static_Low)
                          or else not Model.Is_Well_Formed (Choice.Static_High)
                        then
                           Add (Invalid_Fact, "/variants/choice", "range bound facts are malformed");
                        elsif Profile = Strict_Consumer
                          and then
                            (Choice.Static_Low.Status /= Model.Known
                             or else Choice.Static_High.Status /= Model.Known)
                        then
                           Add (Imprecise_Mandatory_Fact, "/variants/choice", "range bounds must be exact");
                        end if;
                        Check_Selector_Value
                          (Choice.Static_Low, "/variants/choice/static_low");
                        Check_Selector_Value
                          (Choice.Static_High, "/variants/choice/static_high");
                        Check_Direct_Literal_Agreement
                          (Choice.Low,
                           Choice.Static_Low,
                           "/variants/choice/static_low");
                        Check_Direct_Literal_Agreement
                          (Choice.High,
                           Choice.Static_High,
                           "/variants/choice/static_high");
                     end case;
                  end loop;
               end;
               for Component_ID of Alternative.Component_IDs loop
                  if not Component_Exists (Component_ID) then
                     Add (Unresolved_Reference, "/variants/" & ID & "/alternatives/components", "variant component does not resolve");
                  else
                     for Component of Document.Components loop
                        if Model.Image (Component.Stable_ID) = Component_ID then
                           if Model.Image (Component.Owner_ID)
                             /= Model.Image (Part.Owner_ID)
                           then
                              Add (Invalid_Variant, "/variants/" & ID, "variant component has a different owner");
                           end if;
                           declare
                              In_Path : Boolean := False;
                           begin
                              for Path_ID of Component.Variant_Path loop
                                 In_Path := In_Path
                                   or else Path_ID
                                     = Model.Image (Alternative.Stable_ID);
                              end loop;
                              if not In_Path then
                                 Add (Invalid_Variant, "/variants/" & ID, "component path omits its alternative");
                              end if;
                           end;
                        end if;
                     end loop;
                  end if;
               end loop;
               if Model.US.Length (Alternative.Nested_Variant_ID) > 0 then
                  if not Variant_Exists (Model.Image (Alternative.Nested_Variant_ID)) then
                     Add (Unresolved_Reference, "/variants/" & ID & "/alternatives/nested_variant_id", "nested variant does not resolve");
                  elsif Variant_Reaches (Model.Image (Alternative.Nested_Variant_ID), ID, 0) then
                     Add (Invalid_Variant, "/variants/" & ID, "variant containment graph must be acyclic");
                  else
                     for Nested of Document.Variants loop
                        if Model.Image (Nested.Stable_ID)
                          = Model.Image (Alternative.Nested_Variant_ID)
                          and then
                            (Model.Image (Nested.Parent_Alternative_ID)
                               /= Model.Image (Alternative.Stable_ID)
                             or else Model.Image (Nested.Owner_ID)
                               /= Model.Image (Part.Owner_ID))
                        then
                           Add (Invalid_Variant, "/variants/" & ID, "nested variant parent/owner link is inconsistent");
                        end if;
                     end loop;
                  end if;
               end if;
               Alternative_Position := Alternative_Position + 1;
            end loop;
         end;
      end loop;

      return Result;
   end Validate;

end Flyology_Type_IR.Validation;
