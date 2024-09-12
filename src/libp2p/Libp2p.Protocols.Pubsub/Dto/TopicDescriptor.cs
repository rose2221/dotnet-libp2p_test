// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: TopicDescriptor.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021, 8981
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace Nethermind.Libp2p.Protocols.Pubsub.Dto {

  /// <summary>Holder for reflection information generated from TopicDescriptor.proto</summary>
  public static partial class TopicDescriptorReflection {

    #region Descriptor
    /// <summary>File descriptor for TopicDescriptor.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static TopicDescriptorReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "ChVUb3BpY0Rlc2NyaXB0b3IucHJvdG8i3gIKD1RvcGljRGVzY3JpcHRvchIM",
            "CgRuYW1lGAEgASgJEicKBGF1dGgYAiABKAsyGS5Ub3BpY0Rlc2NyaXB0b3Iu",
            "QXV0aE9wdHMSJQoDZW5jGAMgASgLMhguVG9waWNEZXNjcmlwdG9yLkVuY09w",
            "dHMacgoIQXV0aE9wdHMSMAoEbW9kZRgBIAEoDjIiLlRvcGljRGVzY3JpcHRv",
            "ci5BdXRoT3B0cy5BdXRoTW9kZRIMCgRrZXlzGAIgAygMIiYKCEF1dGhNb2Rl",
            "EggKBE5PTkUQABIHCgNLRVkQARIHCgNXT1QQAhp5CgdFbmNPcHRzEi4KBG1v",
            "ZGUYASABKA4yIC5Ub3BpY0Rlc2NyaXB0b3IuRW5jT3B0cy5FbmNNb2RlEhEK",
            "CWtleUhhc2hlcxgCIAMoDCIrCgdFbmNNb2RlEggKBE5PTkUQABINCglTSEFS",
            "RURLRVkQARIHCgNXT1QQAkIpqgImTmV0aGVybWluZC5MaWJwMnAuUHJvdG9j",
            "b2xzLlB1YnN1Yi5EdG8="));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { },
          new pbr::GeneratedClrTypeInfo(null, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor), global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Parser, new[]{ "Name", "Auth", "Enc" }, null, null, null, new pbr::GeneratedClrTypeInfo[] { new pbr::GeneratedClrTypeInfo(typeof(global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts), global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts.Parser, new[]{ "Mode", "Keys" }, null, new[]{ typeof(global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts.Types.AuthMode) }, null, null),
            new pbr::GeneratedClrTypeInfo(typeof(global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts), global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts.Parser, new[]{ "Mode", "KeyHashes" }, null, new[]{ typeof(global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts.Types.EncMode) }, null, null)})
          }));
    }
    #endregion

  }
  #region Messages
  [global::System.Diagnostics.DebuggerDisplayAttribute("{ToString(),nq}")]
  public sealed partial class TopicDescriptor : pb::IMessage<TopicDescriptor>
  #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      , pb::IBufferMessage
  #endif
  {
    private static readonly pb::MessageParser<TopicDescriptor> _parser = new pb::MessageParser<TopicDescriptor>(() => new TopicDescriptor());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pb::MessageParser<TopicDescriptor> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptorReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public TopicDescriptor() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public TopicDescriptor(TopicDescriptor other) : this() {
      name_ = other.name_;
      auth_ = other.auth_ != null ? other.auth_.Clone() : null;
      enc_ = other.enc_ != null ? other.enc_.Clone() : null;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public TopicDescriptor Clone() {
      return new TopicDescriptor(this);
    }

    /// <summary>Field number for the "name" field.</summary>
    public const int NameFieldNumber = 1;
    private readonly static string NameDefaultValue = "";

    private string name_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public string Name {
      get { return name_ ?? NameDefaultValue; }
      set {
        name_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }
    /// <summary>Gets whether the "name" field is set</summary>
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool HasName {
      get { return name_ != null; }
    }
    /// <summary>Clears the value of the "name" field</summary>
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void ClearName() {
      name_ = null;
    }

    /// <summary>Field number for the "auth" field.</summary>
    public const int AuthFieldNumber = 2;
    private global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts auth_;
    /// <summary>
    /// AuthOpts and EncOpts are unused as of Oct 2018, but
    /// are planned to be used in future.
    /// </summary>
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts Auth {
      get { return auth_; }
      set {
        auth_ = value;
      }
    }

    /// <summary>Field number for the "enc" field.</summary>
    public const int EncFieldNumber = 3;
    private global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts enc_;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts Enc {
      get { return enc_; }
      set {
        enc_ = value;
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override bool Equals(object other) {
      return Equals(other as TopicDescriptor);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public bool Equals(TopicDescriptor other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (Name != other.Name) return false;
      if (!object.Equals(Auth, other.Auth)) return false;
      if (!object.Equals(Enc, other.Enc)) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override int GetHashCode() {
      int hash = 1;
      if (HasName) hash ^= Name.GetHashCode();
      if (auth_ != null) hash ^= Auth.GetHashCode();
      if (enc_ != null) hash ^= Enc.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void WriteTo(pb::CodedOutputStream output) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      output.WriteRawMessage(this);
    #else
      if (HasName) {
        output.WriteRawTag(10);
        output.WriteString(Name);
      }
      if (auth_ != null) {
        output.WriteRawTag(18);
        output.WriteMessage(Auth);
      }
      if (enc_ != null) {
        output.WriteRawTag(26);
        output.WriteMessage(Enc);
      }
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalWriteTo(ref pb::WriteContext output) {
      if (HasName) {
        output.WriteRawTag(10);
        output.WriteString(Name);
      }
      if (auth_ != null) {
        output.WriteRawTag(18);
        output.WriteMessage(Auth);
      }
      if (enc_ != null) {
        output.WriteRawTag(26);
        output.WriteMessage(Enc);
      }
      if (_unknownFields != null) {
        _unknownFields.WriteTo(ref output);
      }
    }
    #endif

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public int CalculateSize() {
      int size = 0;
      if (HasName) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(Name);
      }
      if (auth_ != null) {
        size += 1 + pb::CodedOutputStream.ComputeMessageSize(Auth);
      }
      if (enc_ != null) {
        size += 1 + pb::CodedOutputStream.ComputeMessageSize(Enc);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(TopicDescriptor other) {
      if (other == null) {
        return;
      }
      if (other.HasName) {
        Name = other.Name;
      }
      if (other.auth_ != null) {
        if (auth_ == null) {
          Auth = new global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts();
        }
        Auth.MergeFrom(other.Auth);
      }
      if (other.enc_ != null) {
        if (enc_ == null) {
          Enc = new global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts();
        }
        Enc.MergeFrom(other.Enc);
      }
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public void MergeFrom(pb::CodedInputStream input) {
    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
      input.ReadRawMessage(this);
    #else
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
      if ((tag & 7) == 4) {
        // Abort on any end group tag.
        return;
      }
      switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 10: {
            Name = input.ReadString();
            break;
          }
          case 18: {
            if (auth_ == null) {
              Auth = new global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts();
            }
            input.ReadMessage(Auth);
            break;
          }
          case 26: {
            if (enc_ == null) {
              Enc = new global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts();
            }
            input.ReadMessage(Enc);
            break;
          }
        }
      }
    #endif
    }

    #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    void pb::IBufferMessage.InternalMergeFrom(ref pb::ParseContext input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
      if ((tag & 7) == 4) {
        // Abort on any end group tag.
        return;
      }
      switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, ref input);
            break;
          case 10: {
            Name = input.ReadString();
            break;
          }
          case 18: {
            if (auth_ == null) {
              Auth = new global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts();
            }
            input.ReadMessage(Auth);
            break;
          }
          case 26: {
            if (enc_ == null) {
              Enc = new global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts();
            }
            input.ReadMessage(Enc);
            break;
          }
        }
      }
    }
    #endif

    #region Nested types
    /// <summary>Container for nested types declared in the TopicDescriptor message type.</summary>
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
    public static partial class Types {
      [global::System.Diagnostics.DebuggerDisplayAttribute("{ToString(),nq}")]
      public sealed partial class AuthOpts : pb::IMessage<AuthOpts>
      #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
          , pb::IBufferMessage
      #endif
      {
        private static readonly pb::MessageParser<AuthOpts> _parser = new pb::MessageParser<AuthOpts>(() => new AuthOpts());
        private pb::UnknownFieldSet _unknownFields;
        private int _hasBits0;
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public static pb::MessageParser<AuthOpts> Parser { get { return _parser; } }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public static pbr::MessageDescriptor Descriptor {
          get { return global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Descriptor.NestedTypes[0]; }
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        pbr::MessageDescriptor pb::IMessage.Descriptor {
          get { return Descriptor; }
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public AuthOpts() {
          OnConstruction();
        }

        partial void OnConstruction();

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public AuthOpts(AuthOpts other) : this() {
          _hasBits0 = other._hasBits0;
          mode_ = other.mode_;
          keys_ = other.keys_.Clone();
          _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public AuthOpts Clone() {
          return new AuthOpts(this);
        }

        /// <summary>Field number for the "mode" field.</summary>
        public const int ModeFieldNumber = 1;
        private readonly static global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts.Types.AuthMode ModeDefaultValue = global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts.Types.AuthMode.None;

        private global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts.Types.AuthMode mode_;
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts.Types.AuthMode Mode {
          get { if ((_hasBits0 & 1) != 0) { return mode_; } else { return ModeDefaultValue; } }
          set {
            _hasBits0 |= 1;
            mode_ = value;
          }
        }
        /// <summary>Gets whether the "mode" field is set</summary>
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public bool HasMode {
          get { return (_hasBits0 & 1) != 0; }
        }
        /// <summary>Clears the value of the "mode" field</summary>
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public void ClearMode() {
          _hasBits0 &= ~1;
        }

        /// <summary>Field number for the "keys" field.</summary>
        public const int KeysFieldNumber = 2;
        private static readonly pb::FieldCodec<pb::ByteString> _repeated_keys_codec
            = pb::FieldCodec.ForBytes(18);
        private readonly pbc::RepeatedField<pb::ByteString> keys_ = new pbc::RepeatedField<pb::ByteString>();
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public pbc::RepeatedField<pb::ByteString> Keys {
          get { return keys_; }
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public override bool Equals(object other) {
          return Equals(other as AuthOpts);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public bool Equals(AuthOpts other) {
          if (ReferenceEquals(other, null)) {
            return false;
          }
          if (ReferenceEquals(other, this)) {
            return true;
          }
          if (Mode != other.Mode) return false;
          if(!keys_.Equals(other.keys_)) return false;
          return Equals(_unknownFields, other._unknownFields);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public override int GetHashCode() {
          int hash = 1;
          if (HasMode) hash ^= Mode.GetHashCode();
          hash ^= keys_.GetHashCode();
          if (_unknownFields != null) {
            hash ^= _unknownFields.GetHashCode();
          }
          return hash;
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public override string ToString() {
          return pb::JsonFormatter.ToDiagnosticString(this);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public void WriteTo(pb::CodedOutputStream output) {
        #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
          output.WriteRawMessage(this);
        #else
          if (HasMode) {
            output.WriteRawTag(8);
            output.WriteEnum((int) Mode);
          }
          keys_.WriteTo(output, _repeated_keys_codec);
          if (_unknownFields != null) {
            _unknownFields.WriteTo(output);
          }
        #endif
        }

        #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        void pb::IBufferMessage.InternalWriteTo(ref pb::WriteContext output) {
          if (HasMode) {
            output.WriteRawTag(8);
            output.WriteEnum((int) Mode);
          }
          keys_.WriteTo(ref output, _repeated_keys_codec);
          if (_unknownFields != null) {
            _unknownFields.WriteTo(ref output);
          }
        }
        #endif

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public int CalculateSize() {
          int size = 0;
          if (HasMode) {
            size += 1 + pb::CodedOutputStream.ComputeEnumSize((int) Mode);
          }
          size += keys_.CalculateSize(_repeated_keys_codec);
          if (_unknownFields != null) {
            size += _unknownFields.CalculateSize();
          }
          return size;
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public void MergeFrom(AuthOpts other) {
          if (other == null) {
            return;
          }
          if (other.HasMode) {
            Mode = other.Mode;
          }
          keys_.Add(other.keys_);
          _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public void MergeFrom(pb::CodedInputStream input) {
        #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
          input.ReadRawMessage(this);
        #else
          uint tag;
          while ((tag = input.ReadTag()) != 0) {
          if ((tag & 7) == 4) {
            // Abort on any end group tag.
            return;
          }
          switch(tag) {
              default:
                _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
                break;
              case 8: {
                Mode = (global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts.Types.AuthMode) input.ReadEnum();
                break;
              }
              case 18: {
                keys_.AddEntriesFrom(input, _repeated_keys_codec);
                break;
              }
            }
          }
        #endif
        }

        #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        void pb::IBufferMessage.InternalMergeFrom(ref pb::ParseContext input) {
          uint tag;
          while ((tag = input.ReadTag()) != 0) {
          if ((tag & 7) == 4) {
            // Abort on any end group tag.
            return;
          }
          switch(tag) {
              default:
                _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, ref input);
                break;
              case 8: {
                Mode = (global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.AuthOpts.Types.AuthMode) input.ReadEnum();
                break;
              }
              case 18: {
                keys_.AddEntriesFrom(ref input, _repeated_keys_codec);
                break;
              }
            }
          }
        }
        #endif

        #region Nested types
        /// <summary>Container for nested types declared in the AuthOpts message type.</summary>
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public static partial class Types {
          public enum AuthMode {
            [pbr::OriginalName("NONE")] None = 0,
            [pbr::OriginalName("KEY")] Key = 1,
            [pbr::OriginalName("WOT")] Wot = 2,
          }

        }
        #endregion

      }

      [global::System.Diagnostics.DebuggerDisplayAttribute("{ToString(),nq}")]
      public sealed partial class EncOpts : pb::IMessage<EncOpts>
      #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
          , pb::IBufferMessage
      #endif
      {
        private static readonly pb::MessageParser<EncOpts> _parser = new pb::MessageParser<EncOpts>(() => new EncOpts());
        private pb::UnknownFieldSet _unknownFields;
        private int _hasBits0;
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public static pb::MessageParser<EncOpts> Parser { get { return _parser; } }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public static pbr::MessageDescriptor Descriptor {
          get { return global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Descriptor.NestedTypes[1]; }
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        pbr::MessageDescriptor pb::IMessage.Descriptor {
          get { return Descriptor; }
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public EncOpts() {
          OnConstruction();
        }

        partial void OnConstruction();

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public EncOpts(EncOpts other) : this() {
          _hasBits0 = other._hasBits0;
          mode_ = other.mode_;
          keyHashes_ = other.keyHashes_.Clone();
          _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public EncOpts Clone() {
          return new EncOpts(this);
        }

        /// <summary>Field number for the "mode" field.</summary>
        public const int ModeFieldNumber = 1;
        private readonly static global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts.Types.EncMode ModeDefaultValue = global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts.Types.EncMode.None;

        private global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts.Types.EncMode mode_;
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts.Types.EncMode Mode {
          get { if ((_hasBits0 & 1) != 0) { return mode_; } else { return ModeDefaultValue; } }
          set {
            _hasBits0 |= 1;
            mode_ = value;
          }
        }
        /// <summary>Gets whether the "mode" field is set</summary>
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public bool HasMode {
          get { return (_hasBits0 & 1) != 0; }
        }
        /// <summary>Clears the value of the "mode" field</summary>
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public void ClearMode() {
          _hasBits0 &= ~1;
        }

        /// <summary>Field number for the "keyHashes" field.</summary>
        public const int KeyHashesFieldNumber = 2;
        private static readonly pb::FieldCodec<pb::ByteString> _repeated_keyHashes_codec
            = pb::FieldCodec.ForBytes(18);
        private readonly pbc::RepeatedField<pb::ByteString> keyHashes_ = new pbc::RepeatedField<pb::ByteString>();
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public pbc::RepeatedField<pb::ByteString> KeyHashes {
          get { return keyHashes_; }
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public override bool Equals(object other) {
          return Equals(other as EncOpts);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public bool Equals(EncOpts other) {
          if (ReferenceEquals(other, null)) {
            return false;
          }
          if (ReferenceEquals(other, this)) {
            return true;
          }
          if (Mode != other.Mode) return false;
          if(!keyHashes_.Equals(other.keyHashes_)) return false;
          return Equals(_unknownFields, other._unknownFields);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public override int GetHashCode() {
          int hash = 1;
          if (HasMode) hash ^= Mode.GetHashCode();
          hash ^= keyHashes_.GetHashCode();
          if (_unknownFields != null) {
            hash ^= _unknownFields.GetHashCode();
          }
          return hash;
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public override string ToString() {
          return pb::JsonFormatter.ToDiagnosticString(this);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public void WriteTo(pb::CodedOutputStream output) {
        #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
          output.WriteRawMessage(this);
        #else
          if (HasMode) {
            output.WriteRawTag(8);
            output.WriteEnum((int) Mode);
          }
          keyHashes_.WriteTo(output, _repeated_keyHashes_codec);
          if (_unknownFields != null) {
            _unknownFields.WriteTo(output);
          }
        #endif
        }

        #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        void pb::IBufferMessage.InternalWriteTo(ref pb::WriteContext output) {
          if (HasMode) {
            output.WriteRawTag(8);
            output.WriteEnum((int) Mode);
          }
          keyHashes_.WriteTo(ref output, _repeated_keyHashes_codec);
          if (_unknownFields != null) {
            _unknownFields.WriteTo(ref output);
          }
        }
        #endif

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public int CalculateSize() {
          int size = 0;
          if (HasMode) {
            size += 1 + pb::CodedOutputStream.ComputeEnumSize((int) Mode);
          }
          size += keyHashes_.CalculateSize(_repeated_keyHashes_codec);
          if (_unknownFields != null) {
            size += _unknownFields.CalculateSize();
          }
          return size;
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public void MergeFrom(EncOpts other) {
          if (other == null) {
            return;
          }
          if (other.HasMode) {
            Mode = other.Mode;
          }
          keyHashes_.Add(other.keyHashes_);
          _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
        }

        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public void MergeFrom(pb::CodedInputStream input) {
        #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
          input.ReadRawMessage(this);
        #else
          uint tag;
          while ((tag = input.ReadTag()) != 0) {
          if ((tag & 7) == 4) {
            // Abort on any end group tag.
            return;
          }
          switch(tag) {
              default:
                _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
                break;
              case 8: {
                Mode = (global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts.Types.EncMode) input.ReadEnum();
                break;
              }
              case 18: {
                keyHashes_.AddEntriesFrom(input, _repeated_keyHashes_codec);
                break;
              }
            }
          }
        #endif
        }

        #if !GOOGLE_PROTOBUF_REFSTRUCT_COMPATIBILITY_MODE
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        void pb::IBufferMessage.InternalMergeFrom(ref pb::ParseContext input) {
          uint tag;
          while ((tag = input.ReadTag()) != 0) {
          if ((tag & 7) == 4) {
            // Abort on any end group tag.
            return;
          }
          switch(tag) {
              default:
                _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, ref input);
                break;
              case 8: {
                Mode = (global::Nethermind.Libp2p.Protocols.Pubsub.Dto.TopicDescriptor.Types.EncOpts.Types.EncMode) input.ReadEnum();
                break;
              }
              case 18: {
                keyHashes_.AddEntriesFrom(ref input, _repeated_keyHashes_codec);
                break;
              }
            }
          }
        }
        #endif

        #region Nested types
        /// <summary>Container for nested types declared in the EncOpts message type.</summary>
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
        [global::System.CodeDom.Compiler.GeneratedCode("protoc", null)]
        public static partial class Types {
          public enum EncMode {
            [pbr::OriginalName("NONE")] None = 0,
            [pbr::OriginalName("SHAREDKEY")] Sharedkey = 1,
            [pbr::OriginalName("WOT")] Wot = 2,
          }

        }
        #endregion

      }

    }
    #endregion

  }

  #endregion

}

#endregion Designer generated code
