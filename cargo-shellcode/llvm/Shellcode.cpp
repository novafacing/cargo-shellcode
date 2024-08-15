/// LLVM passes to transform a program into a single function, with no data
/// references, appropriate for use as shellcode

#include <llvm/ADT/PostOrderIterator.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/Error.h>
#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/IPO/GlobalDCE.h>

using namespace llvm;

namespace {
/// Pass to inline all functions into the entrypoint (`_start` or `main`)
class InlineFunctions {
private:
  /// The module to run over
  Module &M;
  /// The analysis manager for the module
  ModuleAnalysisManager &MAM;
  /// The call graph of the module
  std::unique_ptr<CallGraph> CG;
  /// The analyses which can be preserved after these transformation
  PreservedAnalyses PA;

public:
  /// Constructor
  InlineFunctions(Module &module,
                  ModuleAnalysisManager &module_analysis_manager)
      : M(module), MAM(module_analysis_manager),
        CG(std::make_unique<CallGraph>(module)), PA(PreservedAnalyses::all()) {}

  /// Get the set of functions called by the function at `Node`
  std::set<Function *> getCalledFunctions(CallGraphNode *Node) const {
    errs() << "Getting called functions...\n";
    std::set<Function *> Callees;
    std::transform(
        Node->begin(), Node->end(), std::inserter(Callees, Callees.begin()),
        [](std::pair<std::optional<WeakTrackingVH>, CallGraphNode *> Node) {
          return Node.second->getFunction();
        });

    std::vector<Function *> CalleesVec(Callees.begin(), Callees.end());

    while (!CalleesVec.empty()) {
      auto Top = CalleesVec.back();
      CalleesVec.pop_back();
      auto TopNode = CG->getOrInsertFunction(Top);

      for (auto CIT = TopNode->begin(), E = TopNode->end(); CIT != E; ++CIT) {
        auto CalleeFunction = CIT->second->getFunction();

        if (Callees.find(CalleeFunction) == Callees.end()) {
          Callees.insert(CalleeFunction);
          CalleesVec.push_back(CalleeFunction);
        }
      }
    }
    return Callees;
  }

  /// Inline all functions into the entry point by marking them as always
  /// inline, then running the always inline pass
  void inlineFunctions() {
    auto Main = M.getFunction("_start");

    if (!Main) {
      auto Main = M.getFunction("main");
    }

    if (!Main) {
      errs() << "No main  or _start function found\n";
      report_fatal_error("No main or _start function found");
    }

    errs() << "Inlining functions into " << Main->getName().str() << "...\n";

    auto TLIWP = TargetLibraryInfoWrapperPass();

    for (Function &F : M) {
      if (&F == Main) {
        continue;
      }
      errs() << "Inlining: " << F.getName().str() << "\n";

      LibFunc LibraryFunction;
      TargetLibraryInfo TLI = TLIWP.getTLI(F);
      bool IsLibrary = TLI.getLibFunc(F.getName(), LibraryFunction);

      if (IsLibrary) {
        errs() << "Function " << F.getName().str() << " is a library function"
               << "\n";
        report_fatal_error(
            (std::string("Function ") + F.getName().str() + " is not available")
                .c_str());
      }

      // Mark analyses as non preserved
      PA = PreservedAnalyses::none();

      // Make the function inlinable
      F.removeFnAttr(Attribute::NoInline);
      F.removeFnAttr(Attribute::OptimizeNone);
      F.addFnAttr(Attribute::AlwaysInline);
    }

    errs() << "Running inliner pass...\n";

    // Run the inliner to force inline everything into the main function (this
    // works recursively)
    auto InlinerResult = AlwaysInlinerPass(false).run(M, MAM);

    errs() << "Removing functions...\n";

    while (M.getFunctionList().size() > 1) {
      for (Function &F : M) {
        if (&F == Main) {
          continue;
        }

        errs() << "Removing function " << F.getName().str() << "...\n";
        F.replaceAllUsesWith(PoisonValue::get(F.getType()));
        F.eraseFromParent();
        break;
      }
    }

    errs() << "Removing dead code...\n";

    // Remove newly dead code resulting from inlining
    GlobalDCEPass().run(M, MAM);

    errs() << "Checking for remaining functions...\n";

    // Ensure only one function remains
    if (std::distance(M.begin(), M.end()) != 1) {

      std::string Functions;

      for (Function &F : M) {
        Functions += F.getName().str() + ", ";
      }

      errs() << "Too many functions after inlining: " << Functions << "\n";
      report_fatal_error(
          (std::string("Only one function should remain after inlining, got ") +
           Functions)
              .c_str());
    }
  }

  /// Remove undefined calls to now-nonexistent functions
  void removeUndefCalls() {
    errs() << "Removing undefined calls...\n";
    std::set<CallInst *> CallInstrs;
    for (auto &F : M) {
      for (auto &BB : F) {
        for (auto &I : BB) {
          if (auto PossiblyPoisonCall = dyn_cast<CallInst>(&I)) {
            CallInstrs.insert(PossiblyPoisonCall);
          }
        }
      }
    }

    for (auto &PossiblyPoisonCall : CallInstrs) {
      if (isa<PoisonValue>(PossiblyPoisonCall->getCalledOperand())) {
        PossiblyPoisonCall->eraseFromParent();
      }
    }
  }

  /// Run the analysis, verifying the module afterward
  PreservedAnalyses run() {
    inlineFunctions();
    if (verifyModule(M)) {
      errs() << "Module is not valid after inlining! Something went terribly "
                "wrong.\n"
             << "Do not use the inline keyword in your input!\n";
      report_fatal_error("Module is not valid! Something went terribly wrong.\n"
                         "Do not use the inline keyword in your input!\n");
    }

    removeUndefCalls();

    if (verifyModule(M)) {
      errs() << "Module is not valid after removing undefined! Something went "
                "terribly wrong.\n"
             << "Do not use the inline keyword in your input!\n";
      report_fatal_error("Module is not valid! Something went terribly wrong.\n"
                         "Do not use the inline keyword in your input!\n");
    }

    return PA;
  }
};

/// Pass to inline global variables into functions
class InlineGlobals {
private:
  /// The module to run over
  Module &M;
  /// The analysis manager for the module
  ModuleAnalysisManager &MAM;
  /// The call graph of the module
  std::unique_ptr<CallGraph> CG;

public:
  /// Constructor
  InlineGlobals(Module &module, ModuleAnalysisManager &module_analysis_manager)
      : M(module), MAM(module_analysis_manager),
        CG(std::make_unique<CallGraph>(module)) {}

  static Function *getGlobalUser(Value &V) {
    Function *F = nullptr;

    SmallVector<User *, 4> Users(V.user_begin(), V.user_end());
    SmallSet<User *, 4> Visited;

    while (!Users.empty()) {
      User *U = Users.pop_back_val();

      if (!Visited.insert(U).second) {
        continue;
      }

      // If the user is a global variable and is not discardable, there is no
      // valid global user
      if (isa<GlobalVariable>(U) &&
          !cast<GlobalVariable>(U)->isDiscardableIfUnused()) {
        return nullptr;
      }

      // If the user is a constant expression, aggregate, or another global, we
      // work from the users of that user instead.
      if (isa<ConstantExpr>(U) || isa<ConstantAggregate>(U) ||
          isa<GlobalVariable>(U)) {
        for (User *UU : U->users()) {
          Users.push_back(UU);
        }

        continue;
      }

      if (Instruction *I = dyn_cast<Instruction>(U)) {
        if (!F) {
          F = I->getParent()->getParent();
        }

        if (I->getParent()->getParent() != F) {
          // If more than one function uses this global, we can't inline it
          // TODO: Just duplicate the global in this case
          return nullptr;
        }
      } else {
        return nullptr;
      }
    }

    return F;
  }

  /// From LLVM llvm/lib/Transforms/IPO/GlobalOpt.cpp@e277d6a
  ///
  /// C may have non-instruction users. Can all of those users be turned into
  /// instructions?
  static bool allNonInstructionUsersCanBeMadeInstructions(Constant *C) {
    // We don't do this exhaustively. The most common pattern that we really
    // need to care about is a constant GEP or constant bitcast - so just
    // looking through one single ConstantExpr.
    //
    // The set of constants that this function returns true for must be able to
    // be handled by makeAllConstantUsesInstructions.
    for (auto *U : C->users()) {
      if (isa<Instruction>(U))
        continue;
      if (!isa<ConstantExpr>(U))
        // Non instruction, non-constantexpr user; cannot convert this.
        return false;
      for (auto *UU : U->users())
        if (!isa<Instruction>(UU))
          // A constantexpr used by another constant. We don't try and recurse
          // any further but just bail out at this point.
          return false;
    }

    return true;
  }

  /// From LLVM llvm/lib/Transforms/IPO/GlobalOpt.cpp@e277d6a
  ///
  /// C may have non-instruction users, and
  /// allNonInstructionUsersCanBeMadeInstructions has returned true. Convert the
  /// non-instruction users to instructions.
  static void makeAllConstantUsesInstructions(Constant *C) {
    SmallVector<ConstantExpr *, 4> Users;
    for (auto *U : C->users()) {
      if (isa<ConstantExpr>(U))
        Users.push_back(cast<ConstantExpr>(U));
      else
        // We should never get here; allNonInstructionUsersCanBeMadeInstructions
        // should not have returned true for C.
        assert(
            isa<Instruction>(U) &&
            "Can't transform non-constantexpr non-instruction to instruction!");
    }

    SmallVector<Value *, 4> UUsers;
    for (auto *U : Users) {
      UUsers.clear();
      append_range(UUsers, U->users());
      for (auto *UU : UUsers) {
        Instruction *UI = cast<Instruction>(UU);
        Instruction *NewU = U->getAsInstruction(UI);
        UI->replaceUsesOfWith(U, NewU);
      }
      // We've replaced all the uses, so destroy the constant. (destroyConstant
      // will update value handles and metadata.)
      U->destroyConstant();
    }
  }

  /// Determine whether a global variable should be inlined and if so, into what
  /// function. Globals must have only one user.
  static Function *shouldInline(GlobalVariable &GV) {
    Function *GlobalUser = nullptr;
    if (!GV.isDiscardableIfUnused()) {
      errs() << "Global variable " << GV.getName()
             << " is not discardable if unused\n";
      return GlobalUser;
    }

    GlobalUser = getGlobalUser(GV);

    if (!GlobalUser) {
      errs() << "Global variable " << GV.getName() << " has no global user\n";
      return GlobalUser;
    }

    return GlobalUser;
  }

  /// Transform aggregate data types (structs, arrays) into non-aggregate types
  static void
  disaggregateVars(Instruction *After, Value *Ptr,
                   SmallVectorImpl<Value *> &Indices, ConstantAggregate &CA,
                   SmallSetVector<GlobalVariable *, 4> &GlobalVariables) {
    SmallSetVector<Value *, 4> ToUndefine;

    Constant *Element = nullptr;

    // Iterate over each element in the aggregate
    for (unsigned ElementIndex = 0;
         (Element = CA.getAggregateElement(ElementIndex)); ++ElementIndex) {

      Indices.push_back(ConstantInt::get(
          Type::getInt32Ty(After->getParent()->getContext()), ElementIndex));

      if (isa<ConstantAggregate>(Element)) {
        // If the elment is an aggregate, recurse into it
        disaggregateVars(After, Ptr, Indices, cast<ConstantAggregate>(*Element),
                         GlobalVariables);
      } else if (isa<ConstantExpr>(Element) ||
                 (isa<GlobalVariable>(Element) &&
                  GlobalVariables.count(cast<GlobalVariable>(Element)))) {
        // Otherwise if the element is a constant expression or a global
        // variable present in the global variable set

        // Generate an instruction to extract the element's location
        GetElementPtrInst *GEP =
            GetElementPtrInst::CreateInBounds(CA.getType(), Ptr, Indices);

        // Insert the instruction after the last instruction
        GEP->insertAfter(After);

        // Add the element to the set of values to undefine
        ToUndefine.insert(Element);

        // Add a store instruction to store the element into the extracted
        // location
        StoreInst *SI = new StoreInst(Element, GEP, GEP->getNextNode());

        After = SI;
      }

      Indices.pop_back();
    }

    for (Value *V : ToUndefine) {
      V->replaceAllUsesWith(UndefValue::get(V->getType()));
    }
  }

  /// Transform a store instruction of an aggregate type with constant value
  /// into multiple store instructions of non-aggregate type with constant value
  static void
  extractValuesFromStore(StoreInst *SI,
                         SmallSetVector<GlobalVariable *, 4> &GlobalVariables) {
    Value *V = SI->getValueOperand();

    // Values do not need to be extracted unless they are an aggregate
    if (!isa<ConstantAggregate>(V)) {
      return;
    }

    // Indices eventually used to construct a GEP
    SmallVector<Value *, 4> Indices = {
        ConstantInt::get(Type::getInt32Ty(SI->getParent()->getContext()), 0)};

    disaggregateVars(SI, SI->getPointerOperand(), Indices,
                     cast<ConstantAggregate>(*V), GlobalVariables);
  }

  /// Inline all global variables into the functions which use them
  static void
  inlineGlobals(Function *F,
                SmallSetVector<GlobalVariable *, 4> GlobalVariables) {
    BasicBlock &BB = F->getEntryBlock();
    Instruction *InsertionPoint = &*BB.getFirstInsertionPt();

    SmallMapVector<GlobalVariable *, Instruction *, 4> StackReplacements;
    StoreInst *FirstStoreInst = nullptr;

    for (GlobalVariable *GV : GlobalVariables) {
      Instruction *GlobalVariableAlloca =
          new AllocaInst(GV->getValueType(), GV->getType()->getAddressSpace(),
                         nullptr, GV->getAlign().valueOrOne(), "",
                         FirstStoreInst ? FirstStoreInst : InsertionPoint);
      GlobalVariableAlloca->takeName(GV);
      StackReplacements[GV] = GlobalVariableAlloca;

      if (GV->hasInitializer()) {
        Constant *GVInitializer = GV->getInitializer();
        StoreInst *NewGVInitializer =
            new StoreInst(GVInitializer, GlobalVariableAlloca, InsertionPoint);
        GV->setInitializer(nullptr);

        extractValuesFromStore(NewGVInitializer, GlobalVariables);

        if (!FirstStoreInst) {
          FirstStoreInst = NewGVInitializer;
        }
      }
    }

    for (auto &P : StackReplacements) {
      makeAllConstantUsesInstructions(P.first);

      P.first->replaceAllUsesWith(P.second);
      P.first->eraseFromParent();
    }
  }

  /// Run the analysis
  PreservedAnalyses run() {
    errs() << "Running global inliner pass...\n";
    SmallMapVector<Function *, SmallSetVector<GlobalVariable *, 4>, 4>
        UsersToGlobalVariables;

    for (GlobalVariable &GV : M.globals()) {
      if (Function *F = shouldInline(GV)) {
        UsersToGlobalVariables[F].insert(&GV);
      }
    }

    for (auto &P : UsersToGlobalVariables) {
      for (GlobalVariable *GV : P.second) {
        errs() << "Inlining global variable " << GV->getName() << " into "
               << P.first->getName() << "\n";
      }
      inlineGlobals(P.first, P.second);
    }

    if (verifyModule(M)) {
      errs() << "Module is not valid! Something went terribly wrong.\n"
             << "Do not use the inline keyword in your input!\n";
      report_fatal_error("Module is not valid! Something went terribly wrong.\n"
                         "Do not use the inline keyword in your input!\n");
    }

    if (UsersToGlobalVariables.empty()) {
      return PreservedAnalyses::all();
    } else {
      PreservedAnalyses PA;
      PA.preserveSet<CFGAnalyses>();
      return PA;
    }
  }
};

struct InlineFunctionsPass : PassInfoMixin<InlineFunctionsPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    return InlineFunctions(M, MAM).run();
  }

  static bool isRequired() { return true; }
};

struct InlineGlobalsPass : PassInfoMixin<InlineGlobalsPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    return InlineGlobals(M, MAM).run();
  }

  static bool isRequired() { return true; }
};

} // namespace

/// Register the function and global variable inlining passes
llvm::PassPluginLibraryInfo getShellcodePluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "Shellcode", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "InlineFunctions") {
                    MPM.addPass(InlineFunctionsPass());
                    return true;
                  } else if (Name == "InlineGlobals") {
                    MPM.addPass(InlineGlobalsPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getShellcodePluginInfo();
}
