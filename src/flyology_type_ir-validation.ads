with Ada.Containers.Vectors;
with Flyology_Type_IR.Model;

package Flyology_Type_IR.Validation is
   pragma Preelaborate;

   type Validation_Profile is (Structural, Strict_Consumer);
   type Severity is (Error, Warning);
   type Diagnostic_Code is
     (Unsupported_IR_Version,
      Unknown_Required_Feature,
      Invalid_Semantic_ID,
      Duplicate_Semantic_ID,
      Unresolved_Reference,
      Invalid_Fact,
      Missing_Mandatory_Fact,
      Imprecise_Mandatory_Fact,
      Invalid_Variant,
      Duplicate_Declaration_Order,
      Anonymous_Type_Rejected);

   type Diagnostic is record
      Level   : Severity := Error;
      Code    : Diagnostic_Code := Invalid_Fact;
      Path    : Model.Text;
      Message : Model.Text;
   end record;

   package Diagnostic_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Diagnostic);

   function Validate
     (Document : Model.IR_Document;
      Profile  : Validation_Profile)
      return Diagnostic_Vectors.Vector;

   function Has_Errors (Diagnostics : Diagnostic_Vectors.Vector) return Boolean;

   --  Structural facts are immutable input to consumer overlays. Overlays may
   --  add policy in their own model, but may never replace even an apparently
   --  equal IR fact; this also avoids mutable-expression aliasing.
   function Overlay_Replacement_Allowed
     (Original  : Model.Semantic_Fact;
      Candidate : Model.Semantic_Fact) return Boolean;
end Flyology_Type_IR.Validation;
