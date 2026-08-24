with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Text_IO;

with Langkit_Support.Text;
with Langkit_Support.Slocs;
with Libadalang.Analysis;
with Libadalang.Common;
with Libadalang.Helpers;

procedure Flyology_Type_IR_LAL_Probe is
   use Ada.Characters.Handling;
   use Ada.Strings;
   use Ada.Strings.Fixed;
   use Ada.Text_IO;
   use Langkit_Support.Text;
   use Langkit_Support.Slocs;
   use Libadalang.Analysis;
   use Libadalang.Common;

   Failed         : Boolean := False;
   Processed_Unit : Boolean := False;

   function Natural_Image (Value : Natural) return String is
     (Trim (Natural'Image (Value), Both));

   function Node_Text (Node : Ada_Node'Class) return String is
     (Image (Node.Text));

   function Canonical_Name (Declaration : Basic_Decl'Class) return String is
     (To_Lower (Image (Declaration.P_Canonical_Fully_Qualified_Name)));

   procedure Reject (Message : String) is
   begin
      Put_Line (Standard_Error, "unsupported extraction shape: " & Message);
      Failed := True;
   end Reject;

   function Safe_Field (Value : String; What : String) return Boolean is
   begin
      for Character of Value loop
         if Character = ASCII.HT
           or else Character = ASCII.LF
           or else Character = ASCII.CR
         then
            Reject (What & " contains a control separator");
            return False;
         end if;
      end loop;
      return True;
   end Safe_Field;

   procedure Emit
     (Kind : String;
      A    : String := "";
      B    : String := "";
      C    : String := "";
      D    : String := "";
      E    : String := "")
   is
      procedure Put_Field (Value : String) is
      begin
         Put (ASCII.HT & Value);
      end Put_Field;
   begin
      Put (Kind);
      if A'Length > 0 or else B'Length > 0 or else C'Length > 0
        or else D'Length > 0 or else E'Length > 0
      then
         Put_Field (A);
      end if;
      if B'Length > 0 or else C'Length > 0 or else D'Length > 0
        or else E'Length > 0
      then
         Put_Field (B);
      end if;
      if C'Length > 0 or else D'Length > 0 or else E'Length > 0 then
         Put_Field (C);
      end if;
      if D'Length > 0 or else E'Length > 0 then
         Put_Field (D);
      end if;
      if E'Length > 0 then
         Put_Field (E);
      end if;
      New_Line;
   end Emit;

   procedure Process_Type (Declaration : Type_Decl) is
      Definition : constant Type_Def := Declaration.F_Type_Def;
      Owner      : constant String := Canonical_Name (Declaration);
      Display    : constant String := Node_Text (Declaration.F_Name);
      Sloc       : constant Source_Location_Range := Declaration.Sloc_Range;
   begin
      if not Declaration.F_Discriminants.Is_Null
        or else not Declaration.F_Aspects.Is_Null
      then
         Reject (Owner & " has discriminants or aspects");
         return;
      end if;
      if not Safe_Field (Owner, "type canonical name")
        or else not Safe_Field (Display, "type display name")
      then
         return;
      end if;

      case Definition.Kind is
         when Ada_Enum_Type_Def =>
            Emit
              ("TYPE", Owner, Display, "enumeration",
               Natural_Image (Natural (Sloc.Start_Line)),
               Natural_Image (Natural (Sloc.Start_Column)));
            declare
               Position : Natural := 0;
            begin
               for Literal of Definition.As_Enum_Type_Def.F_Enum_Literals loop
                  declare
                     Name : constant String := Node_Text (Literal.F_Name);
                  begin
                     if Safe_Field (Name, "enumeration literal") then
                        Emit ("LITERAL", Owner, Natural_Image (Position), Name);
                     end if;
                  end;
                  Position := Position + 1;
               end loop;
            end;

         when Ada_Array_Type_Def =>
            declare
               Array_Definition : constant Array_Type_Def :=
                 Definition.As_Array_Type_Def;
               Indices          : constant Array_Indices :=
                 Array_Definition.F_Indices;
               Component_Type   : constant Base_Type_Decl :=
                 Array_Definition.F_Component_Type.F_Type_Expr
                   .P_Designated_Type_Decl;
               Index_Count      : Natural := 0;
               Index_Type       : Base_Type_Decl := No_Base_Type_Decl;
            begin
               if Array_Definition.F_Component_Type.F_Has_Aliased then
                  Reject (Owner & " has aliased array components");
                  return;
               end if;
               if not Array_Definition.F_Component_Type.F_Type_Expr
                 .P_Subtype_Constraint.Is_Null
               then
                  Reject (Owner & " has a constrained component subtype");
                  return;
               end if;
               if Indices.Kind /= Ada_Constrained_Array_Indices then
                  Reject (Owner & " is not a constrained array");
                  return;
               end if;
               for Index_Node of Indices.As_Constrained_Array_Indices.F_List loop
                  Index_Count := Index_Count + 1;
                  if Index_Node.Kind /= Ada_Subtype_Indication then
                     Reject (Owner & " index is not a subtype indication");
                  else
                     if not Index_Node.As_Subtype_Indication.F_Constraint.Is_Null then
                        Reject (Owner & " has an explicit index constraint");
                     end if;
                     Index_Type := Index_Node.As_Subtype_Indication
                       .P_Designated_Type_Decl;
                  end if;
               end loop;
               if Index_Count /= 1 or else Index_Type.Is_Null then
                  Reject (Owner & " must have exactly one resolved index");
                  return;
               end if;
               Emit
                 ("TYPE", Owner, Display, "array",
                  Natural_Image (Natural (Sloc.Start_Line)),
                  Natural_Image (Natural (Sloc.Start_Column)));
               Emit
                 ("ARRAY", Owner, Canonical_Name (Index_Type),
                  Canonical_Name (Component_Type));
            end;

         when Ada_Record_Type_Def =>
            declare
               Record_Definition : constant Record_Type_Def :=
                 Definition.As_Record_Type_Def;
               Components        : constant Component_List :=
                 Record_Definition.F_Record_Def.F_Components;
               Position          : Natural := 0;
            begin
               if Record_Definition.F_Has_Abstract
                 or else Record_Definition.F_Has_Tagged
                 or else Record_Definition.F_Has_Limited
                 or else not Components.F_Variant_Part.Is_Null
               then
                  Reject (Owner & " is not a plain nonvariant record");
                  return;
               end if;
               Emit
                 ("TYPE", Owner, Display, "record",
                  Natural_Image (Natural (Sloc.Start_Line)),
                  Natural_Image (Natural (Sloc.Start_Column)));
               for Item of Components.F_Components loop
                  if Item.Kind /= Ada_Component_Decl then
                     Reject (Owner & " contains a non-component declaration");
                  else
                     declare
                        Component : constant Component_Decl :=
                          Item.As_Component_Decl;
                        Target    : constant Base_Type_Decl :=
                          Component.F_Component_Def.F_Type_Expr
                            .P_Designated_Type_Decl;
                     begin
                        if Component.F_Component_Def.F_Has_Aliased
                          or else Component.F_Component_Def.F_Has_Constant
                          or else not Component.F_Default_Expr.Is_Null
                          or else not Component.F_Aspects.Is_Null
                          or else not Component.F_Component_Def.F_Type_Expr
                            .P_Subtype_Constraint.Is_Null
                        then
                           Reject
                             (Owner & " contains a qualified/defaulted component");
                        end if;
                        for Name_Node of Component.F_Ids loop
                           declare
                              Name : constant String := Node_Text (Name_Node);
                           begin
                              if Safe_Field (Name, "component name") then
                                 Emit
                                   ("COMPONENT", Owner,
                                    Natural_Image (Position), Name,
                                    Canonical_Name (Target));
                              end if;
                           end;
                           Position := Position + 1;
                        end loop;
                     end;
                  end if;
               end loop;
            end;

         when others =>
            Reject (Owner & " uses " & Definition.Kind'Image);
      end case;
   end Process_Type;

   procedure Process_Unit
     (Context : Libadalang.Helpers.App_Job_Context;
      Unit    : Analysis_Unit)
   is
      pragma Unreferenced (Context);

      function Visit (Node : Ada_Node'Class) return Visit_Status is
      begin
         if Node.Kind = Ada_Package_Decl then
            declare
               Package_Node : constant Package_Decl := Node.As_Package_Decl;
            begin
               if not Package_Node.F_Private_Part.Is_Null
                 or else not Package_Node.F_Aspects.Is_Null
               then
                  Reject ("package private parts and aspects are outside the slice");
               end if;
               for Declaration of Package_Node.F_Public_Part.F_Decls loop
                  if Declaration.Kind not in Ada_Type_Decl then
                     Reject ("package contains a non-type public declaration");
                  end if;
               end loop;
            end;
         end if;
         if Node.Kind in Ada_Type_Decl then
            Process_Type (Node.As_Type_Decl);
            return Over;
         end if;
         return Into;
      end Visit;
   begin
      if Processed_Unit then
         Reject ("more than one source unit was selected");
         return;
      end if;
      Processed_Unit := True;
      if Unit.Has_Diagnostics then
         for Diagnostic of Unit.Diagnostics loop
            Put_Line (Standard_Error, Unit.Format_GNU_Diagnostic (Diagnostic));
         end loop;
         Failed := True;
      elsif Unit.Root.Is_Null then
         Reject ("analysis unit has no root");
      else
         Emit ("PROBE", "1", Unit.Get_Filename);
         Unit.Root.Traverse (Visit'Access);
      end if;
   exception
      when Property_Error =>
         Reject ("Libadalang name resolution failed");
   end Process_Unit;

   package Application is new Libadalang.Helpers.App
     (Name               => "flyology_type_ir_lal_probe",
      Description        => "Emit closed semantic evidence for Type IR v1",
      Process_Unit       => Process_Unit,
      Enable_Parallelism => False);
begin
   Application.Run;
   if Failed or else not Processed_Unit then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Flyology_Type_IR_LAL_Probe;
