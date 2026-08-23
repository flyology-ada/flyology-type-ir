with Flyology_Type_IR.Model;

package Flyology_Type_IR.Canonical_JSON is
   pragma Preelaborate;

   Unsupported_Version : exception;
   Invalid_Document    : exception;
   Noncanonical_Input  : exception;

   --  This interface deliberately has no permissive default implementation.
   --  A codec must reject duplicate keys and unsupported versions before
   --  interpreting semantic fields, reject unknown fields in version 1, and
   --  compare a strict parse/re-emit against the original canonical bytes.
   type Codec is limited interface;

   function Encode
     (Implementation : Codec;
      Document       : Model.IR_Document) return String is abstract;

   --  Canonical interchange contains diagnostic/audit material and its byte
   --  hash is therefore not a semantic fingerprint. This operation emits the
   --  normative source-independent projection defined in canonical-json.md.
   function Encode_Semantic_Projection
     (Implementation : Codec;
      Document       : Model.IR_Document) return String is abstract;

   function Decode
     (Implementation : Codec;
      UTF_8_JSON     : String) return Model.IR_Document is abstract;
end Flyology_Type_IR.Canonical_JSON;
